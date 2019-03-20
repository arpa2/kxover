/* tcpwrap -- TCP/TLS wrapping around backend KDC and STARTTLS/KXOVER.
 *
 * The TCP wrapper relies on the UDP backend, which implements resends
 * to establish (somewhat) reliable "connections" to the backend KDC.
 * It is like the UDP wrapper, but differs on details.  For one, it
 * needs to maintain a window buffer.  And of course it needs to take
 * a length prefix into account, with its possible alternative use as
 * a flag word.
 *
 * The only TCP flag understood today is STARTTLS, which is required
 * as protection of KXOVER messages.  Other messages than KXOVER are
 * passed to the backend KDC as before, over an unprotected UDP port
 * as these messages will be sent locally, and unconnected.
 *
 * KX-OFFER messaging is handled locally.  The TCP wrapper should
 * only receive requests, to which it would send a response or
 * failure, after validating the client KDC through its certificate
 * being mentioned in DANE under DNSSEC.  Another module can act as
 * a client, sending an initial KX-OFFER to a server over another
 * TCP connection within STARTTLS.
 *
 * The TLS facilities, including DANE/DNSSEC validation, are drawn
 * from the TLS Pool.  This is a separate daemon process that
 * conceals the private key for our KDC and that simply replaces
 * our unprotected file handle with one that is protected, along
 * with structures to exchange more information about identities.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include "tcpwrap.h"
#include "backend.h"
#include "kxover.h"
#include "starttls.h"
#include "socket.h"

#include <stdio.h>


#ifdef DEBUG
#  define DPRINTF printf
#else
#  define DPRINTF(...)
#endif


/* The acceptdata structure holds anything needed to
 * allow accept() detection and teardown administration.
 */
struct acceptdata {
	struct acceptdata *next;
	int socket;
	ev_io acceptor;
};


/* The wrapdata structure holds the event listener and other
 * descriptive information for the socket.  Since it is
 * permitted to process only one Kerberos message at a time
 * for a TCP connection, we will take that liberty.
 *
 * The flags field holds accumulated flags; the high bit is
 * set if even just a PROBE came by once; the low bit is set
 * when STARTTLS has been requested (which is immediately
 * initiated, though not necessarily validated yet).
 */
struct wrapdata {
	//TODO:DONT// struct wrapdata *next;
	int socket;
	int sendctr;
	ev_io listener;
	struct sockaddr_storage client;
	uint32_t flags;
	uint32_t progress;
	uint8_t *reqptr;
	uint32_t reqlen;
	uint32_t reqofs;
	uint8_t *repptr;
	uint32_t replen;
	uint32_t repofs;
	struct starttls_data *tlsdata;
	struct kxover_data *kxover;
};
#define PROGRESS_TLS             0x00000001
#define PROGRESS_CLIENT_HOSTNAME 0x00000002
#define PROGRESS_SERVER_HOSTNAME 0x00000004


/* The list of TCP acceptors that have been created.
 */
static struct acceptdata *tcpacceptors = NULL;


/* The list of TCP wrappers that have been created.
 */
//TODO//NOT_MANAGED// static struct wrapdata *tcpwrappers = NULL;


/* The event loop used by the TCP wrapper.
 */
struct ev_loop *tcpwrap_loop = NULL;


static void _listener_handler (struct ev_loop *loop, ev_io *evt, int revents);


static void cb_starttls_handshaken (void *cbdata, int fd_new) {
	struct wrapdata *wd = cbdata;
	/* Forget the old socket, regardless of the new one */
	wd->socket = fd_new;
	/* When the TLS handshake failed, disconnect */
	if (fd_new < 0) {
		goto disconnect;
	}
	/* Flag willingness to take on KXOVER */
	wd->progress |= PROGRESS_TLS;
	/* Switch back to TCP processing, but now on fd_new */
	ev_io_set (&wd->listener, fd_new, EV_READ /* TODO:FORBIDDEN: | EV_ERROR */);
	ev_io_start (tcpwrap_loop, &wd->listener);
	/* Done, finish */
DPRINTF ("cb_starttls_handshaken() succeeds and traffic will be read from %d\n", fd_new);
	return;
disconnect:
	if (wd->socket >= 0) {
		/* This should also close the TLS handler... in general? */
		close (wd->socket);
	}
	starttls_close (wd->tlsdata);
	free (wd);
}


/* Backend callback function to write out the request.
 * This may be called more than once, if the backend calls
 * for resends due to a non-responsive KDC.  We return
 * true to stop the backend when we have been sending for
 * too long.
 */
static bool cb_write_request (struct backend *beh, void *cbdata) {
	struct wrapdata *wd = cbdata;
	assert (beh != NULL);
	assert (wd  != NULL);
	if (wd->sendctr++ > 3) {
		/* Sent several attempts, stop trying */
		goto disconnect;
	}
	backend_send (beh, wd->reqptr, wd->reqlen);
	goto retry;
disconnect:
	close (wd->socket);
	if (wd->tlsdata != NULL) {
		starttls_close (wd->tlsdata);
	}
	free (wd);
	return true;
retry:
	return false;
/*TODO*FUTURE*OPTION*
 * nextmsg:
 * 	ev_io_start (loop, wd->listener);
 * 	return true;
 */
}


/* Backend callback function to read in the response.  When
 * the response matches our request, we return true so as to
 * stop the backend.
 *
 * We should match the message as well as we can.  There is
 * a risk that we pass on an older message to a newer client,
 * as a result of our proxy function with reuse of backends.
 * Any matching before passing on reduces this risk.
 */
static bool cb_read_response (struct backend *beh, void *cbdata) {
	struct wrapdata *wd = cbdata;
	assert (beh != NULL);
	assert (wd  != NULL);
	uint8_t buf [4+1500+1];
	uint32_t buflen = 1500+1;
	free (wd->reqptr);
	wd->reqptr = NULL;
	if (!backend_recv (beh, buf+4, &buflen)) {
		goto retry;
	}
	if ((buflen < 1) || (buflen > 1500)) {
		goto disconnect;
	}
	* (uint32_t *) buf = htonl (buflen);
	//TODO:IMPLEMENT// Match response against request
	/* Actually send; TCP is reliable, but clients check */
	send (wd->socket, buf, 4+buflen, 0);
nextmsg:
	ev_io_start (tcpwrap_loop, &wd->listener);
	return true;
disconnect:
	close (wd->socket);
	if (wd->tlsdata != NULL) {
		starttls_close (wd->tlsdata);
	}
	free (wd);
	return true;
retry:
	return false;
}


/* Callback function from the KXOVER server, indicating success
 * or failure.  Note that the wrapdata->reqptr holds data that is
 * referenced internally by the kxover_server() until it triggers
 * the callback.  Within the callback, the only data that may
 * point into the wrapdata->kxdata are the client_realm and the
 * service_realm provided to the callback.  We do not clean up
 * the kxover administration data, but stop referencing it here,
 * because it will be cleaned up after this call completes.
 */
static void tcpwrap_cb_kxover_done (void *cbdata,
			int result_errno,
			struct dercursor client_realm,
			struct dercursor service_realm) {
	struct wrapdata *wd = cbdata;
if ((service_realm.derptr != NULL) && (client_realm.derptr != NULL))
DPRINTF ("DEBUG: tcpwrap_cb_kxover_done() called for krbtgt/%.*s@%.*s\n",
service_realm.derlen, service_realm.derptr,
client_realm.derlen, client_realm.derptr);
	if (result_errno != 0) {
		//TODO// Report failure to even setup the kxover_server
DPRINTF ("DEBUG: Failed while running the kxover_server: %d (%s)\n", result_errno, strerror (result_errno));
		goto disconnect;
	}
	/* We kept wd->reqptr for the realm strings, but can clean now */
	if (wd->reqptr != NULL) {
		free (wd->reqptr);
		wd->reqptr = NULL;
	}
	/* We simply forget; the KXOVER server cleans up after itself */
	wd->kxover = NULL;
	//TODO// Continue TLS connection on success
disconnect:
DPRINTF ("DEBUG: Wrong! Bad! Evil! Will shut down the socket to tcpwrap_cb_kxover_done()\n");
	close (wd->socket);
	if (wd->tlsdata != NULL) {
		starttls_close (wd->tlsdata);
	}
	if (wd->reqptr != NULL) {
		free (wd->reqptr);
	}
	free (wd);
}


/* Callback function for reading from a socket, and forwarding
 * of the Kerberos message to the backend KDC.
 *
 * This function reads a Kerberos message from the TCP port and
 * allocates a backend for sending it, and for processing the
 * response.  Until the response has been processed, no other
 * activities are read from the same TCP port, so a TCP socket
 * processes just one operation at a time.
 *
 * The TCP layer adds flags, notably PROBE and STARTTLS.  The
 * PROBE is handled locally and STARTTLS is answered and then
 * the TCP connection is temporarily delegated to the starttls
 * module to start a TLS handshake in server mode.
 */
static void _listener_handler (struct ev_loop *loop, ev_io *evt, int revents) {
	struct wrapdata *wd = 
		(struct wrapdata *) (
			((uint8_t *) evt) -
				offsetof (struct wrapdata, listener));
	/* See if the connection was closed or otherwise in error */
	if (revents & EV_ERROR) {
		goto disconnect;
	}
	/* Load the initial 4 byte word, with length or TCP flags */
	uint8_t len_flags_buf [4] = { 0,0,0,0 };
	if (wd->reqptr == NULL) {
		ssize_t recvlen = recv (wd->socket, len_flags_buf, 4, 0);
		if (recvlen == -1) {
			if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
				/* Simply not ready for reading yet */
				return;
			}
		} else if (recvlen != 4) {
			/* We insist on these 4 bytes not trickling in */
			goto disconnect;
		}
	}
	/* Handle TCP flags, if any */
	uint32_t len_flags = ntohl (* (uint32_t *) len_flags_buf);
DPRINTF ("_listener_handler() received 0x%08x as length/flags prefix\n", len_flags);
	if (len_flags & 0x80000000) {
		if (len_flags == 0x80000000) {
			/* PROBE flag, tell it about STARTTLS */
			* (uint32_t *) len_flags_buf = htonl (0x80000001);
			if (send (wd->socket, len_flags_buf, 4, 0) != 4) {
				/* Failed send to reliable channel, exit */
				goto disconnect;
			}
		} else if (len_flags == 0x80000001) {
			/* Make sure that we are not nesting TLS inside TLS */
			if ((wd->progress & 0x00000001) == 0x00000001) {
				/* Profusely refuse to confuse or diffuse the obtuse */
				goto disconnect;
			}
			/* STARTTLS flag -- acknowledge to the client */
			uint8_t starttls_ok [4] = { 0x00, 0x00, 0x00, 0x00 };
			if (send (wd->socket, starttls_ok, 4, 0) != 4) {
				/* Failed send to reliable channel, exit */
				goto disconnect;
			}
			/* Now stop TCP processing and delegate TLS */
			ev_io_stop (loop, evt);
			dercursor dernull = { .derptr = NULL, .derlen = 0 };
			if (!starttls_handshake (wd->socket,
						dernull, dernull, /* No names yet */
						&wd->tlsdata,
						cb_starttls_handshaken, wd));
			if (wd->tlsdata == NULL) {
				goto disconnect_stopped;
			}
		} else {
			/* Unrecognised flags, disconnect */
			goto disconnect;
		}
		/* Take note of successfully processed flags (after success) */
		wd->flags |= len_flags;
		/* No continued processing when we just handled flags */
		return;
	}
	/* Handle TCP length, if new, setting the req buffer */
	if (wd->reqptr == NULL) {
		if ((len_flags < 10) || (len_flags > 1500)) {
			/* Silly length, bail out */
			goto disconnect;
		}
		wd->reqlen = len_flags;
		wd->reqofs = 0;
		wd->reqptr = calloc (wd->reqlen, 1);
		if (wd->reqptr == NULL) {
			/* Out of memory, bail out of TCP connection */
			goto disconnect;
		}
	}
	/* Load the data and client address into temporary buffers */
	assert (wd->reqlen > 0);
	assert (wd->reqofs < wd->reqlen);
	ssize_t recvlen = recv (wd->socket,
				wd->reqptr + wd->reqofs,
				wd->reqlen - wd->reqofs,
				0);
	if (recvlen <= 0) {
		/* Funny size, ignore this attempt */
		return;
	}
	/* Update the buffer and see if more is needed */
	wd->reqofs += recvlen;
	if (wd->reqofs < wd->reqlen) {
		/* Not yet done, continue in future calls */
		return;
	}
	/* Stop interrupts from the upstream for now */
	ev_io_stop (loop, evt);
	/* Sidetrack (away from backend) for KXOVER traffic */
	struct dercursor msg;
	msg.derptr = wd->reqptr;
	msg.derlen = wd->reqlen;
	switch (kxover_classify_kerberos_down (msg)) {
	case TCPKRB5_PASS:
		/* Literally pass Kerberos data (u2d2u) */
DPRINTF ("DEBUG: Received a message to pass literally\n");
		break;
	case TCPKRB5_KXOVER_REQ:
		/* Sidetrack: Handle as KXOVER request (u2d).
		 * The wd->reqptr serves as backend store until the callback
		 * And even within the callback, the realms are supported by it!
		 */
DPRINTF ("DEBUG: Recognised a KXOVER request\n");
		if ((wd->progress & PROGRESS_TLS) != PROGRESS_TLS) {
			fprintf (stderr, "Attempt to run KXOVER without TLS layer\n");
			goto disconnect_stopped;
		}
		wd->kxover = kxover_server (tcpwrap_cb_kxover_done, wd, wd->tlsdata, msg, wd->socket);
		if (wd->kxover == NULL) {
			/* Report through the callback, but without realms */
			struct dercursor dernull = { .derptr = NULL, .derlen = 0 };
			if (errno == 0) {
				errno = ECONNREFUSED;
			}
			tcpwrap_cb_kxover_done (wd, errno, dernull, dernull);
			/* DO NOT cleanup wd or wd->socket -- the callback does that */
			return;
		}
DPRINTF ("DEBUG: Side-tracked to a KXOVER server\n");
		return;
	case TCPKRB5_ERROR:
	default:
DPRINTF ("DEBUG: Received an unknown or undesired result\n");
		/* Unknown or undesired result */
		goto disconnect_stopped;
	}
	/* Delegate to a backend construct to proxy as UDP with resends */
	if (backend_start (wd, cb_write_request, cb_read_response) == NULL) {
		/* Backend failure, drop the TCP message */
		goto disconnect_stopped;
	}
	return;
disconnect:
	ev_io_stop (loop, evt);
	/* continue... */
disconnect_stopped:
	close (wd->socket);
	if (wd->tlsdata != NULL) {
		starttls_close (wd->tlsdata);
	}
	if (wd->reqptr != NULL) {
		free (wd->reqptr);
	}
	free (wd);
	return;
}


/* Callback function for accepting a new TCP connection, and setting it
 * up as a TCP wrapper, which forwards one or more Kerberos messages to
 * the backend KDC.
 *
 * We marked the socket non-blocking to avoid race conditions due
 * when accept()ing a socket that has been closed remotely, which
 * would block our single process.
 */
static void _acceptor_handler (struct ev_loop *loop, ev_io *evt, int _revents) {
	struct acceptdata *ad = 
		(struct acceptdata *) (
			((uint8_t *) evt) -
				offsetof (struct acceptdata, acceptor));
	/* Allocate the memory to store the new connection */
	struct wrapdata *wd = calloc (1, sizeof (struct wrapdata));
	if (wd == NULL) {
		goto fail;
	}
	/* Try to accept the new connection, and determine the client address */
	socklen_t wdlen = sizeof (wd->client);
	wd->socket = accept (ad->socket, (struct sockaddr *) &wd->client, &wdlen);
	if ((wd->socket < 0) || (wdlen != sockaddrlen ((struct sockaddr *) &wd->client))) {
		/* No work to be done, client may have retracted */
		goto fail;
	}
	/* Start event handling for the wrapdata structure, ERROR for close */
	ev_io_init (&wd->listener, _listener_handler, wd->socket, EV_READ /* NOT_ALLOWED: | EV_ERROR */);
	ev_io_start (loop, &wd->listener);
	/* Enlist the new wrapdata structure */
	ad->next = tcpacceptors;
	tcpacceptors = ad;
	return;
fail:
	if (wd != NULL) {
		free (wd);
	}
	return;
}


/* Initialise the TCP wrapper module.  This must be called
 * before the actual service is started with tcpwrap_service().
 *
 * Return true on success, or false with errno set on failure.
 */
bool tcpwrap_init (struct ev_loop *loop) {
	tcpwrap_loop = loop;
	return true;
}


/* Setup a TCP wrapper to listen to a given address and port.
 * This port would inform us when accept() can be called, which
 * would lead to additional event handlers for the newly created
 * connection.
 *
 * This function may be called more than once.  The address is
 * assumed to be IPv6 formatted, but that includes IPv4 prefixed
 * with two colons.
 *
 * Service starts immediately, so this should not be called before
 * the backend has been initialised.
 *
 * Return true on success, or false with errno set on failure.
 */
bool tcpwrap_service (struct sockaddr *ear) {
	int sox = -1;
	struct wrapdata *wd = NULL;
	struct acceptdata *ad = NULL;
	if (!socket_server (ear, SOCK_STREAM, &sox)) {
		goto fail;
	}
	ad = calloc (1, sizeof (struct acceptdata));
	if (ad == NULL) {
		goto fail;
	}
	ad->socket = sox;
	ad->next = tcpacceptors;
	tcpacceptors = ad;
	/* EV_READ will detect opportunities for accept() */
	ev_io_init (&ad->acceptor, _acceptor_handler, sox, EV_READ);
	ev_io_start (tcpwrap_loop, &ad->acceptor);
	return true;
fail:
	if (ad != NULL) {
		free (ad);
	}
	if (sox != -1) {
		close (sox);
	}
	return false;
}


