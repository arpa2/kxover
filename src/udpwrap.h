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


#ifndef KXOVER_UDPWRAP_H
#define KXOVER_UDPWRAP_H


#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <ev.h>


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
bool udpwrap_init (struct ev_loop *loop, char *addr, uint16_t port);


#endif /* KXOVER_UDPWRAP_H */
