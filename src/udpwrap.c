/* udpwrap -- Accept UDP messages and process like flag-deprived TCP.
 *
 * The minimal task for a UDP wrapper is to avoid KDC-sent errors of the
 * kind KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN to reach the client.  Instead,
 * the client should retry over TCP.  This would slow down processing,
 * and is not advised, even if it is a useful idea to fall back from UDP
 * to TCP to facilitate the delays of KXOVER processing.  (There are no
 * guarantees about the patience of clients though, not even with TCP,
 * so in rare cases a user may have to repeat a request.)
 *
 * But we can do much better than.  When we detect detect errors of the
 * kind KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN we respond to them by initiating
 * realm crossover in the client role.  After this succeeds, the request
 * can be resent.  Clever logic may optimise handling of UDP resends.
 *
 * UDP has no flagging facility, so this can only be used when servicing
 * clients.  KX-OFFER could not be validated, due to the missing STARTTLS
 * flagging, so UDP is unfit for KXOVER communication between KDC's.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


TODO:
We might use UDP backends in all cases, and give clients temporary local UDP sockets
