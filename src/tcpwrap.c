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


#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <errno.h>

#include <libev/ev.h>



/* The acceptdata structure holds anything needed to
 * allow accept() detection and teardown administration.
 */
struct acceptdata {
	struct acceptdata *next;
	int socket;
	ev_io_t acceptor;
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
	ev_io_t listener;
	struct sockaddr_in6 client;
	uint32_t flags;
	uint8_t *reqptr;
	uint32_t reqlen;
	uint32_t reqofs;
	uint8_t *repptr;
	uint32_t replen;
	uint32_t repofs;
	//TODO// tlsdata...
};


/* The list of TCP acceptors that have been created.
 */
static struct acceptdata *tcpacceptors = NULL;


/* The list of TCP wrappers that have been created.
 */
//TODO//NOT_MANAGED// static struct wrapdata *tcpwrappers = NULL;


/* Backend callback function to write out the request.
 * This may be called more than once, if the backend calls
 * for resends due to a non-responsive KDC.  We return
 * true to stop the backend when we have been sending for
 * too long.
 */
static bool cb_write_request (struct backend *beh, struct wrapdata *wd) {
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
static bool cb_read_response (struct backend *beh, struct wrapdata *wd) {
	assert (beh != NULL);
	assert (wd  != NULL);
	uint8_t buf [1500+1];
	uint32_t buflen = 1500+1;
	if (!backend_recv (beh, buf, buflen)) {
		goto retry;
	}
	if ((buflen < 1) || (buflen > 1500)) {
		goto disconnect;
	}
	//TODO:IMPLEMENT// Match response against request
	/* Actually send; TCP is reliable, but clients check */
	send (wd->socket, buf, buflen, 0);
	goto disconnect;
disconnect:
	close (wd->socket);
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
	if (wd->req_flags == NULL) {
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
	if (len_flags & 0x80000000) {
		wd->flags |= len_flags;
		if (len_flags == 0x80000000) {
			/* PROBE flag, tell it about STARTTLS */
			* (uint32_t *) len_flags_buf = htonl (0x80000001);
			if (send (wd->socket, len_flags_buf, 4, 0) != 4) {
				/* Failed send to reliable channel, exit */
				goto disconnect;
			}
		} else if (len_flags == 0x80000001) {
			/* STARTTLS flag -- acknowledge to the client */
			if (send (wd->socket, len_flags_buf, 4, 0) != 4) {
				/* Failed send to reliable channel, exit */
				goto disconnect;
			}
			/* Now stop TCP processing and delegate TLS */
			ev_io_stop (loop, evt);
			starttls_handshake_server (wd, &wd->socket, loop, evt);
		} else {
			/* Unrecognised flags, disconnect */
			goto disconnect;
		}
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
				wd->reqlen - wd->reqofs);
	if (recvlen <= 0) {
		/* Funny size, ignore this attempt */
		return;
	}
	/* Update the buffer and see if more is needed */
	wd->reqofs += recvlen;
	if (wd->reqofs < wd->reqlen) {
		/* Not yet done, continue in future calls */
	}
	/* Delegate to a backend construct to proxy as UDP with resends */
	ev_io_stop (loop, evt);
	if (backend_start (wd, cb_write_request, cb_read_response) == NULL) {
		/* Backend failure, drop the TCP message */
		goto disconnect;
	}
	return;
disconnect:
	ev_io_stop (loop, evt);
	close (wd->socket);
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
	wd->socket = accept (ad->socket, &wd->client, sizeof (wd->client));
	if (wd->socket < 0) {
		/* No work to be done, client may have retracted */
		goto fail;
	}
	/* Start event handling for the wrapdata structure, ERROR for close */
	ev_io_init (&wd->listener, _listener_handler, wd->socket, EV_READ | EV_ERROR);
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


/* Initialise the TCP wrapper module.
 *
 * Return true on success, or false with errno set on failure.
 */
bool tcpwrap_init (void) {
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
bool tcpwrap_listen (struct ev_loop *loop, char *addr, uint16_t port) {
	int sox = -1;
	struct wrapdata *wd = NULL;
	struct sockaddr_in6 sin6;
	switch (inet_pton (AF_INET6, addr, &sin6)) {
	case 1:
		break;
	case 0:
		/* Invalid address did not set errno */
		errno = EINVAL;
		return false;
	default:
		return false;
	}
	sin6.sin6_port = htons (port);
	int sox = socket (AF_INET6, SOCK_STREAM, 0);
	if (sox < 0) {
		goto fail;
	}
	int soxflags = fcntl (sox, F_GETFL, 0);
	if (fcntl (sox, F_SETFL, soxflags | O_NONBLOCK) != 0) {
		goto fail;
	}
	if (bind (sox, &sin6, sizeof (sin6)) != 0) {
		goto fail;
	}
	if (listen (sox, 10) != 0) {
		goto fail;
	}
	struct wrapdata *ad = calloc (1, sizeof (struct acceptdata));
	if (ad == NULL) {
		goto fail;
	}
	ad->socket = sox;
	ad->next = tcpacceptors;
	tcpacceptors = ad;
	/* EV_READ will detect opportunities for accept() */
	ev_io_init (&ad->acceptor, _acceptor_handler, sox, EV_READ);
	ev_io_start (loop, &ad->acceptor);
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

