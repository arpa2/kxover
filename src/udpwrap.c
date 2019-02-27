/* udpwrap -- Accept UDP messages and process like flag-deprived TCP.
 *
 * The basic functionality of the UDP wrapper is to pass Kerberos
 * messages to the KDC via the backend.  There is one special case,
 * and that is when KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN is returned;
 * this would call for KXOVER client behaviour.
 *
 * During the KXOVER transaction, the client will not receive any
 * response (as Kerberos lacks a "please hold, I'm onto it" form).
 * Impatient clients might fall out before KXOVER has been handled,
 * so tricks may be needed, such as a fallback to TCP or perhaps
 * just multiple UDP interfaces that it might try as fallbacks.
 * If all else fails, the user could restart the client after the
 * few seconds it would take them to make up their mind and would
 * normally find if KXOVER had been established.  Not perfect, but
 * workable because it applies to just one client at a time.
 *
 * When the KXOVER attempt fails, or perhaps has even been cached
 * as a previously failed attempt, the error from the KDC would be
 * forwarded to the client.
 *
 * When the KXOVER attempt succeeds, the original request from the
 * client is posted to the backend KDC once more.  It should now
 * resolve to a crossover ticket, which instructs the client to try
 * again on another KDC.  Such crossover tickets take the form
 *    krbtgt/REMOTE.REALM@LOCAL.REALM
 *
 * Any KXOVER messages that would arrive over UDP would have to be
 * rejected, but forwarding to the KDC would cause that in the
 * signature style of the KDC.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include "udpwrap.h"
#include "backend.h"



/* The wrapdata structure holds the event listener and other
 * descriptive information for the socket.
 */
struct wrapdata {
	struct wrapdata *next;
	int socket;
	ev_io listener;
};


/* The structure of a single message being processed.
 * These are used as cbdata (or user data) towards the
 * backend, which will provide it along with callbacks.
 *
 * The structure is created on UDP message reception.
 * The callbacks are supposed to cleanup the storage
 * space when they indicate that the backend is done.
 *
 * It may seem unnecessary to buffer UDP messages, as
 * the client can be trusted to resend.  The reason
 * for doing this is that we would like to respond
 * fast, rather than in response to a resend, when
 * KXOVER succeeds.  We need the client's ticket in
 * such situations, not just the desired service name.
 * Since this disadvantages all UDP traffic for the
 * benefit of a few, this choice is under discussion.
 */
struct udpmsg {
	struct sockaddr_in6 client;
	struct wrapdata *wrapdata;
	uint8_t *reqptr;
	uint32_t reqlen;
	uint8_t *repptr;
	uint32_t replen;
	uint8_t sendctr;
};


/* The list of UDP wrappers that have been created.
 */
static struct wrapdata *udpwrappers = NULL;


/* Backend callback function to write out the request.
 * This may be called more than once, if the backend calls
 * for resends due to a non-responsive KDC.  We return
 * true to stop the backend when we have been sending for
 * too long.
 */
static bool cb_write_request (struct backend *beh, void *cbdata) {
	struct udpmsg *msg = cbdata;
	assert (beh != NULL);
	assert (msg != NULL);
	if (msg->sendctr++ > 3) {
		/* Sent several attempts, stop trying */
		goto cleanup;
	}
	backend_send (beh, msg->reqptr, msg->reqlen);
	return false;
cleanup:
	free (msg);
	return true;
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
	struct udpmsg *msg = cbdata;
	assert (beh != NULL);
	assert (msg != NULL);
	uint8_t buf [1500+1];
	uint32_t buflen = 1500+1;
	if (!backend_recv (beh, buf, &buflen)) {
		goto fail;
	}
	if ((buflen < 1) || (buflen > 1500)) {
		goto fail;
	}
	//TODO:IMPLEMENT// Match response against request
	//
	/* Actually send; UDP is lossy, so no checks made */
	sendto (msg->wrapdata->socket, buf, buflen, 0,
				(struct sockaddr *) &msg->client, sizeof (msg->client));
	free (msg);
	return true;
fail:
	return false;
}


/* Callback function for reading from a socket, and forwarding
 * of the Kerberos message to the backend KDC.
 *
 * This function reads a Kerberos message from the UDP port and
 * allocates a backend for sending it, and for processing the
 * response.  An udpmsg structure is created as user data for
 * which the sending and receiving routines are called.
 */
static void _listener_handler (struct ev_loop *loop, ev_io *evt, int _revents) {
	struct wrapdata *wd = 
		(struct wrapdata *) (
			((uint8_t *) evt) -
				offsetof (struct wrapdata, listener));
	/* Load the data and client address into temporary buffers */
	uint8_t buf [1500+1];
	struct sockaddr_in6 sin6;
	socklen_t sin6len = sizeof (sin6);
	ssize_t recvlen = recvfrom (wd->socket, buf, 1500+1, 0,
				(struct sockaddr *) &sin6, &sin6len);
	if ((sin6len != sizeof (sin6)) || (recvlen <= 0) || (recvlen > 1500)) {
		/* Funny size, drop the UDP message */
		return;
	}
	/* Allocate user data for use in backend callbacks */
	struct udpmsg *msg = calloc (1, sizeof (struct udpmsg) + recvlen);
	if (msg == NULL) {
		/* Out of memory, drop the UDP message */
		return;
	}
	msg->wrapdata = wd;
	msg->reqptr = (uint8_t *) &msg[1];	/* Pointing beyond the structure */
	msg->reqlen = recvlen;
	memcpy (&msg->client, &sin6, sizeof (msg->client));
	memcpy (msg->reqptr, buf, recvlen);
	/* Request a backend construct to proxy the UDP message */
	if (backend_start (msg, cb_write_request, cb_read_response) == NULL) {
		/* Backend failure, drop the UDP message */
		free (msg);
	}
}


/* Initialise an UDP wrapper to listen to a given address and port.
 * This function may be called more than once.  The address is
 * assumed to be IPv6 formatted, but that includes IPv4 prefixed
 * with two colons.
 *
 * Service starts immediately, so this should not be called before
 * the backend has been initialised.
 *
 * Return true on success, or false with errno set on failure.
 */
bool udpwrap_init (struct ev_loop *loop, char *addr, uint16_t port) {
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
	sox = socket (AF_INET6, SOCK_DGRAM, 0);
	if (sox < 0) {
		goto fail;
	}
	int soxflags = fcntl (sox, F_GETFL, 0);
	if (fcntl (sox, F_SETFL, soxflags | O_NONBLOCK) != 0) {
		goto fail;
	}
	if (bind (sox, (struct sockaddr *) &sin6, sizeof (sin6)) != 0) {
		goto fail;
	}
	if (listen (sox, 10) != 0) {
		goto fail;
	}
	wd = calloc (1, sizeof (struct wrapdata));
	if (wd == NULL) {
		goto fail;
	}
	wd->socket = sox;
	wd->next = udpwrappers;
	udpwrappers = wd;
	ev_io_init (&wd->listener, _listener_handler, sox, EV_READ);
	ev_io_start (loop, &wd->listener);
	return true;
fail:
	if (wd != NULL) {
		free (wd);
	}
	if (sox != -1) {
		close (sox);
	}
	return false;
}


