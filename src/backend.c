/* backend pooling, contacting the local KDC over UDP
 *
 * Since Kerberos messages tend to be pretty stateless, it is
 * possible to relay messages one at a time.  Even when mixing
 * multiple senders, and thereby possibly overlapping nonces,
 * we can use a pool of UDP sockets and send one message over
 * each, and possibly use different sockets even when within
 * one upstream TCP connection.  This allows simple pooling of
 * UDP sockets, which are recycled into the pool after reply.
 *
 * The backend is responsible for UDP resends.  That is the
 * one disadvantage of using UDP instead of TCP.
 *
 * This code assumes a single-threaded or asynchronous approach
 * in clients.  For multiple threads, pool operations may have
 * to be locked, or each thread could have its own pool.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/netinet.h>

#include <errno.h>
#include <unistd.h>

#include <libev/ev.h>


/* BACKEND_POOLSIZE limits overlapping backend requests.
 * This rate limits the load passed to the local KDC.
 *
 * //XXX// Or this could rate limit requests per second.
 */
#ifndef BACKEND_POOLSIZE
#define BACKEND_POOLSIZE 512
#endif


/* The callback routines registered for writing and reading.
 * These routines should return true when no further callbacks
 * are required (of either kind) and processing is to be
 * considered complete.
 */
typedef bool (*backend_callback) (struct backend *beh, void *cbdata);


/* The administration of a current pool entry.
 *
 * The central idea is to allocate a unique UDP socket
 * and to report back when something can be written or
 * read.  Writes are ordered upon starting and again
 * after every timeout.  Reads are ordered when data
 * arrives; the recipient should validate that a proper
 * message was received.  When either callback returns
 * true, processing will be stopped.
 *
 * This structure is opaque to other modules, and is
 * used when calling operations in this one.  A cbdata
 * pointer will be replicated during callback, always
 * together with the opaque backend pointer.
 */
struct backend {
	struct backend *next;
	int socket;
	void *cbdata;
	backend_callback cb_write_req;
	backend_callback cb_read_resp;
	ev_timer writer;
	ev_io    reader;
};


/* The first free backend structure in the pool, and a
 * pointer to the NULL element that would be the place
 * to extend the list.  For an empty list, the latter
 * will point to the former.
 */
static struct backend  *_pool     = NULL;
static struct backend **_pool_end = &_pool;


/* The event loop is initialised along with the callback
 * routines through backend_init().
 *
 * Note that we use fixed timing, so it may be possible
 * to setup a single queue and only wait on the first
 * entry with a timer.  The expiration time could be the
 * time to collect backends that had been stopped.
 */
static struct ev_loop *backend_loop;
//TODO//DROP// static void _writer_handler (EV_P_ ev_timer *evt, int _revents);
//TODO//DROP// static void _reader_handler (EV_P_ ev_io    *evt, int _revents);


/* The KDC address as an IPv6 socket address.
 * Since we need access to the KDB too, we assume
 * localhost (over IPv6 of course) and port 88.
 */
static sockaddr_in6 kdc_sockaddr = {
	.sin6_family = AF_INET6,
	.sin6_port = htons (88),
	.sin6_addr = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
};


/* Process a writing event and/or a repeating timeout.
 * Translate this to a callback for writing.  When the
 * callback returns true, trigger backend_stop().
 *
 * TODO:CONSIDER:
 * When backend_stop() is called, it remains on the
 * timer queue, allowing a minimal time for further
 * responses to trickle in from the backend KDC.
 * When the timer expires and we find the backend has
 * already been stopped, we cleanup its timer and we
 * recycle the backend to the pool.  Note that the
 * reading callbacks may continue to fire during all
 * this time; this allows the removal of any further
 * spurious material that might come in.
 */
static void _writer_handler (EV_P_ ev_timer *evt, int _revents) {
	struct backend *beh = 
		(struct backend *) (
			((uint8_t *) evt) -
				offsetof (struct backend, writer));
	/* Test if this backend was stopped and may now be recycled */
	if (beh->cbdata == NULL) {
		assert (beh->cbdata != NULL); //XXX// Is not possible yet
		//XXX// This would always delay the recycling
		ev_timer_stop (backend_loop, &beh->writer);
		*_pool_end = beh;
		_pool_end = &beh->next;
	}
	/* Perform the callback */
	stop_it = beh->cb_write_req (beh, beh->cbdata);
	if (stop_it) {
		backend_stop (beh);
	}
}


/* Receive a reading event for a backend.  When stopped,
 * consume the frame and drop it silently.  It is most
 * likely a response to a retransmission of a request,
 * or a response that simply was received slowly.
 */
static void _reader_handler (EV_P_ ev_io *evt, int _revents) {
	struct backend *beh = 
		(struct backend *) (
			((uint8_t *) evt) -
				offsetof (struct backend, reader));
	/* Test if this data looks spurious; if so, consume and drop it */
	if (beh->cbdata == NULL) {
		uint8_t  dropbuf [1500];
		uint32_t droplen = 1500;
		backend_recv (beh, &dropbuf, &droplen);
		return;
	}
	/* Perform the callback */
	stop_it = beh->cb_read_resp (beh, beh->cbdata);
	if (stop_it) {
		backend_stop (beh);
	}
}


/* Create pool entries.  This is usually called only once,
 * at initialisation time.  The number of entries created
 * is set with the compile-time variable BACKEND_POOLSIZE.
 *
 * Two callback routines are registered; one for writing
 * a request to the backend, and another for reading a
 * response from the same backend.  These functions are
 * considered global and constant.
 *
 * Return true on success, false on failure with errno set.
 */
bool backend_init (struct ev_loop *loop) {
	struct backend *pool = calloc (BACKEND_POOLSIZE, sizeof(backend));
	if (pool == NULL) {
		errno = ENOMEM;
		return false;
	}
	backend_loop = loop;
	int i;
	for (i=0; i<BACKEND_POOLSIZE; i++) {
		int sox = socket (AF_INET, SOCK_DGRAM, 0);
		if (sox < 0) {
			break;
		}
		if (connect (sox, &kdc_sockaddr, sizeof(kdc_sockaddr)) != 0) {
			close (sox);
			break;
		}
		pool [i].socket = sox;
		ev_timer_init (&pool [i].writer, _writer_handler, 2.0, 1.0);
		ev_io_init    (&pool [i].reader, _reader_handler, sox, EV_READ);
		ev_io_start (backend_loop, &pool [i].reader);
		if (_pool == NULL) {
			/* We added a tail element to an empty list */
			_pool_end = &pool [i].next;
		}
		pool [i].next = _pool;
		_pool = pool;
	}
	/* When socket() or connect() failed, they set errno */
	return (_pool != NULL);
}


/* Start a backend process for one request/response interaction.
 *
 * This procedure will initiate callbacks to send a request,
 * possibly multiple times while it is running, and it will
 * initiate callbacks when responses arrive.  At some point,
 * a callback returns true to indicate that processing is
 * complete.
 *
 * Note that the first call to the callback may already be
 * made during this call, so before the backend handle is
 * even shown to the calling environment.
 *
 * Return a handle on success, or NULL with errno set on failure.
 */
struct backend *backend_start (void *cbdata,
			backend_callback cb_write_req,
			backend_callback cb_read_resp) {
	assert (cbdata != NULL);
	struct backend *beh = _pool;
	if (beh == NULL) {
		errno = EBUSY;
		return NULL;
	}
	_pool = _pool->next;
	if (_pool == NULL) {
		/* We removed the last element from the list */
		_pool_end = &_pool;
	}
	beh->cbdata = cbdata;
	beh->cb_write_req = cb_write_req;
	beh->cb_read_resp = cb_read_resp;
	/* Send the first attempt right now */
	cb_write_req (beh, cbdata);
	/* The timer will fire for re-sending */
	ev_timer_start (backend_loop, &beh->writer);
	return beh;
}


/* Stop a backend previously returned by backend_start().
 *
 * The structure is passed to the end of the pool, to reduce
 * problems caused by spurious responses, such as might be due
 * to responses after a timeout, or repeated responses to
 * repeated requests.  This is arranged by setting cbdata in
 * the backend to NULL and allowing the reading events to
 * continue to occur.
 *
 * This function does not fail and does not return a result.
 */
void backend_stop (struct backend *beh) {
	assert (beh != NULL);
	assert (beh->next == NULL);
	assert (*_pool_end == NULL);
	ev_timer_stop (backend_loop, &beh->writer); //XXX//
	beh->cbdata = NULL;
	*_pool_end = beh; //XXX//
	_pool_end = &beh->next; //XXX//
	//XXX//NOTE// These might move into the _writer_handler()
}


/* Send a Kerberos message to the backend KDC.  The function returns
 * a new backend structure, to be used in subsequent calls to this
 * module.
 *
 * Return false on failure with errno set, or true on success.
 */
bool backend_send (struct backend *beh,
		uint8_t const *inptr, const uint32_t inlen) {
	assert (beh != NULL);
	assert (beh->socket >= 0);
	assert (inptr != NULL);
	assert (inlen > 0);
	ssize_t sent = send (pool [pix], inptr, inlen, MSG_DONTWAIT);
	if ((sent >= 0) && (sent != inlen)) {
		/* send() did not set errno, so we will */
		errno = EAGAIN;
	}
	return (sent == inlen);
}


/* Try to retrieve a Kerberos message from the backend KDC.
 * This will only work when backend_send() succeeded before.
 * The buffer must be previously allocated and the outlen
 * is set to its maximum size.  Upon successful return, the
 * value in outlen reflects what was actually read.
 *
 * The backend must still be unlocked explicitly!
 *
 * Return true on success, or false with errno set on failure.
 */
bool backend_recv (struct backend *beh,
			uint8_t *outptr, uint32_t *outlen) {
	assert (beh != NULL);
	assert (beh->socket >= 0);
	assert (outptr != NULL);
	assert (outlen != NULL);
	assert (*outlen > 0);
	ssize_t received = recv (beh->socket, outptr, *outlen, MSG_DONTWAIT);
	if (received > 0) {
		*outlen = received;
		return true;
	} else {
		if (received == 0) {
			/* recv() did not set errno, so we will */
			errno = EAGAIN;
		}
		*outlen = 0;
		return false;
	}
}


