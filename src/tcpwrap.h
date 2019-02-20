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


#ifndef KXOVER_TCPWRAP_H
#define KXOVER_TCPWRAP_H


#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <ev.h>


/* Opaque declarations */
struct backend;


/* Initialise the TCP wrapper module.  This must be called
 * before the actual service is started with tcpwrap_service().
 *
 * Return true on success, or false with errno set on failure.
 */
bool tcpwrap_init (struct ev_loop *loop);


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
bool tcpwrap_service (char *addr, uint16_t port);


#endif /* KXOVER_TCPWRAP_H */
