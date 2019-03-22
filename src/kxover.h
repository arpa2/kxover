/* kxover -- Process KX-OFFER requests between client and service realms.
 *
 * This involves the contents of a Kerberos message, classifying it
 * as KXOVER messaging or other, and when it is KXOVER, handling it.
 * The classification does not imply any rights to be sending this
 * piece of information at this point; the TCP and UDP wrappers are
 * responsible of validating such things.
 *
 * RFC 6251 defines TLS as STARTTLS initiated by a TCP flag,
 * RFC 5021 defines TCP flags as an extension to the TCP transport,
 * RFC 4120 defines the TCP transport in Section 7.2.2.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef KXOVER_H
#define KXOVER_H


#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <com_err.h>
#include <errortable.h>

#include <unistd.h>
#include <fcntl.h>

#include <unbound.h>

#include <quick-der/api.h>
#include <quick-der/rfc4120.h>

#include <ev.h>



/* Opaque declarations */
struct kxover_data;
struct starttls_data;


/* Error codes for the entire KXOVER package, for com_err(), see src/errors.et */
typedef long kxerr_t;
extern kxerr_t kxerrno;


/* The maximum number of bytes in a DERific Kerberos message */
#define MAXLEN_KERBEROS 1500


/* Application tags used in Kerberos with KXOVER extensions */
#define APPTAG_KRB_ERROR  ( 0x40 | 0x20 | 30 )
#define APPTAG_KXOVER_REQ ( 0x40 | 0x20 | 18 )
#define APPTAG_KXOVER_REP ( 0x40 | 0x20 | 19 )


/* The various ways of handling a Kerberos data from upstream or
 * in the response from downstream.
 */
typedef enum tcpkrb5 {
	TCPKRB5_PASS   = 0,	/* Literally pass Kerberos data (u2d2u) */
	TCPKRB5_KXOVER_REQ = 1,	/* Handle as KXOVER request (u2d) */
	TCPKRB5_KXOVER_REP = 2,	/* Handle as KXOVER response (d2u) */
	TCPKRB5_NOTFOUND = 3,	/* Error calling for KXOVER (d2u) */
	TCPKRB5_ERROR = -1
} tcpkrb5_t;


/* Callback routines for reporting KXOVER success or failure
 * to the caller.  Success is reported with kxerrno being zero.
 * The same form is used for the client and server modes of
 * operation.
 *
 * After this has returned, some cleanup takes place, and it
 * is no longer safe to reference the following:
 *  - the structure into which the cbdata was registered,
 *    even just to _cancel() an operation;
 * As a result, the callback must either process the data
 * immediately, or store it elsewhere.  As an exception to
 * this rule, the following will not be cleaned up:
 *  - the client_realm and service_realm.
 * For a client, this means it gets the realms that it
 * initially submitted (with corresponding borrow status).
 * For a server, this means that it needs to free() the
 * memory behind each realm's derptr.
 */
typedef void (*cb_kxover_result) (void *cbdata,
			kxerr_t result_errno,
			struct dercursor client_realm,
			struct dercursor service_realm);


/* Initialise the kxover.c module, setting the event loop it
 * should use.
 *
 * When opt_etc_hosts_file is not NULL, it is configured as
 * Unbound's source of ip/host mappings to report unsecurely.
 *
 * Return true on succes, or false with kxerrno set on failure.
 */
bool kxover_init (EV_P_ char *dnssec_rootkey_file, char *opt_etc_hosts_file);


/* Clean up resources used by kxover.  All running processes must have
 * ended before this is called.
 */
void kxover_fini (void);


/* Having classified a frame from upstream as Kerberos,
 * interpret the read Kerberos data and see if it should be
 * handled as KXOVER, or passed to the downstream.
 *
 * This function always returns a meaningful result.
 * Possible return values are TCPKRB5_PASS, _KXOVER_REQ as
 * well as _ERROR.
 */
tcpkrb5_t kxover_classify_kerberos_down (struct dercursor krb);


/* Having classified TCPKRB5_KXOVER_REQ from upstream,
 * handle it locally by validating the client and, if
 * acceptable, constructing a key for realm crossover
 * and passing back the response.
 *
 * The information supplied to this routine are the
 * KXOVER request that came in, along with the file
 * descriptor over which the answer should be sent.
 *
 * Client validation is partially done by the starttls
 * module, notably the part from the client host name
 * through DANE.  The additional requirement here is
 * to validate the mapping from the client realm name
 * to its server name.  Furthermore, a check that the
 * local/service realm name is supported by the TLS
 * certificate presented locally makes sense, to avoid
 * being open to arbitrary requests and/or relaying.
 * The TLS connection will have been setup outside of
 * the kxover_server() call, and is therefore sent in.
 *
 * This functions starts the KXOVER server process,
 * and returns an opaque object on success, or NULL
 * with kxerrno set otherwise.  When an object is
 * returned, the callback function will be called to
 * report the overall success or failure of the
 * KXOVER operation.
 *
 * The server borrows the ownership of kx_req_frame
 * for the duration of its processing, that data is
 * assumed to be stable until the callback.
 */
struct kxover_data *kxover_server (cb_kxover_result cb, void *cbdata,
			struct starttls_data *tlsdata,
			struct dercursor kx_req_frame, int kxoffer_fd);


/* Having classified TCPKRB5_NOTFOUND from downstream,
 * handle it locally by initiating realm crossover.
 * This involves validation and/or secure lookups.
 *
 * The service that was not found must follow the format
 *
 *    $(SERVICE)/$(HOSTNAME)@$(LOCALREALM)
 *
 * where $(SERVICE) can be anything but "krbtgt", and
 * in which the $(LOCALREALM) will be the client realm
 * during the KXOVER request.  The service realm is
 * found with a secure _kerberos.$(HOSTNAME) TXT lookup
 * and also used in the KXOVER request.  A check may be
 * made to see if no other local nodes are trying the
 * same, or that they have failed before.
 * 
 * Based on the $(REMOTEREALM), we can now perform an
 * SRV lookup to find KDC host names to contact.  This
 * is done over TCP, and immediately starts sending a
 * STARTTLS flag.  After this is accepted by the remote,
 * The starttls module is started with the host names
 * of the local and remote KDC as parameters.
 *
 * Once the TLS Pool establishes a connection, which
 * involves a DANE check for the KDC host named
 * certificates, we only need to check that the
 * realm names occur as SubjectAlternativeName on the
 * local and remote end.
 *
 * At that point, we are ready to send the KXOVER
 * request and await its response.
 *
 * In short, the client realm and service realm are
 * supplied to this routine.  It opens a connection
 * for itself, so a socket is not required.
 *
 * This functions starts the KXOVER client process,
 * and returns an opaque object on success, or NULL
 * with kxerrno set otherwise.  When an object is
 * returned, the callback function will be called to
 * report the overall success or failure of the
 * KXOVER operation.
 */
struct kxover_data *kxover_client (cb_kxover_result cb, void *cbdata,
			struct dercursor client_realm, struct dercursor service_realm);


/* Having classified KRB_ERROR message from downstream,
 * handle it locally by initiating realm crossover and
 * return the structure for its handling.  When done,
 * the callback will be invoked to indicate success or
 * failure in setting up a crossover key and allowing
 * another attempt that should be more successful (if
 * the KDC can infer the home realm for the requested
 * service ticket).
 *
 * Server validation is partially done by the starttls
 * module, notably the part from the server host name
 * through DANE.  Plus, if we sent the KXOVER request
 * before, we know that the server host name was found
 * securely.  The caution that remains here is to see
 * to it that the KXOVER response matches the KXOVER
 * request.
 *
 * This function wraps around kxover_client() and adds
 * parsing of the Kerberos response to determine the
 * client and service realms.  The callback is called
 * with the given callback data and an indication of
 * success, as well as the client and service realms
 * in case of success.
 *
 * The return value is either an opaque object as from
 * kxover_client() or it is NULL to indicate failure
 * to parse or setup the client, with detail in kxerrno.
 * This function will regularly fail, but it can be
 * freely tried.  Other errors or otherwise unfit
 * messages will simply return failure.
 */
struct kxover_data *kxover_client_for_KRB_ERROR (
			cb_kxover_result cb, void *cbdata,
			struct dercursor krbdata);


/* Add a timeout to the given KXOVER handle.  This can be called after
 * a successful kxover_client() or kxover_server() call.  It will lead
 * to an automatic breakdown of communications and a callback with
 * error code ETIMEDOUT when the given time (in seconds) expires before
 * the exchange is done.  Call this again to restart the timer.  Any
 * timeout value <= 0.0 will stop the timer.
 */
void kxover_timeout (struct kxover_data *kxd, float timeout_seconds);


#endif /* KXOVER_H */

