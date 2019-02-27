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


#ifndef KXOVER_BACKEND_H
#define KXOVER_BACKEND_H


#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>

#include <endian.h>
#include <ev.h>

#include <quick-der/api.h>


/* BACKEND_POOLSIZE limits overlapping backend requests.
 * This rate limits the load passed to the local KDC.
 *
 * //XXX// Or this could rate limit requests per second.
 */
#ifndef BACKEND_POOLSIZE
#define BACKEND_POOLSIZE 512
#endif


/* Opaque declarations */
struct backend;


/* The callback routines registered for writing and reading.
 * These routines should return true when no further callbacks
 * are required (of either kind) and processing is to be
 * considered complete.
 */
typedef bool (*backend_callback) (struct backend *beh, void *cbdata);


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
bool backend_init (struct ev_loop *loop);


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
			backend_callback cb_read_resp);


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
void backend_stop (struct backend *beh);


/* Send a Kerberos message to the backend KDC.  The function returns
 * a new backend structure, to be used in subsequent calls to this
 * module.
 *
 * Return false on failure with errno set, or true on success.
 */
bool backend_send (struct backend *beh,
		uint8_t const *inptr, const uint32_t inlen);


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
			uint8_t *outptr, uint32_t *outlen);


#endif /* KXOVER_BACKEND_H */

