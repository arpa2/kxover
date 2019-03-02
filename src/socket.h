/* Socket utilities, including parsing and sockaddr juggling.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef KXOVER_SOCKET_H
#define KXOVER_SOCKET_H


#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>


/* Given a socket address, determine its length.
 *
 * This function does not fail.
 *
 * TODO:inline
 */
socklen_t sockaddrlen (const struct sockaddr *sa);


/* Parse an address and port, and store them in a sockaddr of
 * type AF_INET or AF_INET6.  The space provided is large enough
 * to hold either, as it is defined as a union.
 *
 * The opt_port may be NULL, in which case the port is set to 0
 * in the returned sockaddr; otherwise, its value is rejected
 * if it is 0.
 *
 * We always try IPv6 address parsing first, but fallback to
 * IPv4 if we have to, but that fallback is deprecated.  The
 * port will be syntax-checked and range-checked.
 *
 * Return true on success, or false with errno set on error.
 */
bool socket_parse (char *addr, char *opt_port, struct sockaddr *out_sa);


/* Open a connection as a client, to the given address.  Do not bind locally.
 *
 * Set contype to one SOCK_DGRAM, SOCK_STREAM or SOCK_SEQPACKET.
 *
 * The resulting socket is written to out_sox.
 *
 * Return true on success, or false with errno set on failure.
 */
bool socket_client (const struct sockaddr *peer, int contype, int *out_sox);


/* Open a listening socket as a server, at the given address.
 *
 * Set contype to one of SOCK_DGRAM, SOCK_STREAM or SOCK_SEQPACKET.
 *
 * The resulting socket is written to out_sox.
 *
 * Return true on success, or false with errno set on failure.
 */
bool socket_server (const struct sockaddr *mine, int contype, int *out_sox);


#endif /* KXOVER_SOCKET_H */

