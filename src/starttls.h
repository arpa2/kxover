/* STARTTLS and KDC identity module for Kerberos TCP connections.
 *
 * This module implements the STARTTLS extension to allow Kerberos to run
 * over TLS.  This is a requirement for KXOVER.  TLS setup, in both the
 * client and server variants, is implemented by the TLS Pool.
 *
 * The other requirement for KXOVER is the validation of KDC certificates
 * based on DANE and DNSSEC, which is also implemented here with the help
 * of the TLS Pool:
 *
 *  1. The service host.name is prefixed with _kerberos and looked up
 *     as TXT, which must be secured by DNSSEC;
 *
 *  2. The REALM found there is mapped to a DNS name, and SRV records
 *     for the TLS service is queried, which must be secured by DNSSEC;
 *
 *  3. For the various SRV records found, a TLSA record is looked up
 *     and the validation constraints for the KDC records are found;
 *     this must be secured by DNSSEC;
 *
 *  4. The KDC hostname(s) are looked up as AAAA/A records, which need
 *     not be secured with DNSSEC because KDCs have protecting secrets.
 *
 * In terms of validation, the starttls.c module takes care of just:
 * 
 *  1. Exchange of KDC host names.
 *
 *  2. Ensuring TLS certificates match the KDC host names.
 * 
 *  3. Validating the TLS certificates under DANE/DNSSEC.
 *
 *  3. Testing whether a realm occurs in a TLS certificate as a
 *     SubjectAlternativeName.
 *
 * An important final function for this module is to establish a password
 * that is the same on the client and server.  This will use information
 * from both KX-OFFER messages exchanged under TLS, and it will talk to
 * the TLS Pool to incorporate the master secret under RFC 5705.  The
 * password is a hexadecimal lower-case representation of the shared
 * secret, because textual shared keys are a long-standing practice.
 *
 * All this is done asynchronously, with callbacks from the Unbound and
 * TLS Pool libraries triggering the steps to follow, until finally the
 * client of the starttls can proceed with updated knowledge.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef KXOVER_STARTTLS_H
#define KXOVER_STARTTLS_H


#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <tlspool/commands.h>
#include <tlspool/starttls.h>

#include <quick-der/api.h>

#include <ev.h>



/* Opaque declarations */
struct starttls_data;


/* The cnx_state indicates the stages through which connections progress.
 * This describes any TCP connection, from its initial setup to the
 * stage where the remote identity is known; whether it is valid can be
 * said only when the remote REALM is presented in a KX-OFFER, so it is
 * not accurate to say that a connection can have a valid identity.  The
 * scope of a cnx_state is a TCP connection from accept() to close().
 */
enum cnx_state {
	cnx_resting = 0,
	cnx_starttls,
	cnx_under_tls,
	cnx_remote_id_claimed,
	cnx_error = -1
};


/* The id_state indicates the stages through which identity validation
 * progresses.  This is required for any remote, regardless of its role
 * being the client or server.  Kerberos offers mutual authentication,
 * and KXOVER follows this powerful notion.  The id_state is scoped to
 * each KX-OFFER message separately, so repetitive submissions of such
 * messages will also lead to multiple id_state progressions.  When
 * iterations over SRV and TLSA are nested, this would be reflected as
 * backtracking the id_state in case of dead ends, which is otherwise
 * not to be expected.
 */
enum id_state {
	id_resting = 0,
	id_dnssec_host_txt,
	id_dnssec_kdc_srv,
	id_dnssec_kdc_tlsa,
	id_claimed,
	id_valid,
	id_error = -1
};

	
/* Initialise the starttls module.  This involves preparation of TLS
 * processing with the TLS Pool through its asynchronous API.
 *
 * Return true on success, or false with errno set on failure.
 */
bool starttls_init (EV_P);


/* Perform the STARTTLS deed.  That is, take in a file descriptor
 * and turn it into a TLS-protected file descriptor after going
 * through a TLS handshake.  A control structure is passed, and is
 * assumed to be allocated by the caller, but internally managed
 * by this module -- it may change without notice, dropping any
 * code that references its internals.
 *
 * The file descriptor is not opaque, and is passed separately.
 * The caller must assume that it may be modified during this
 * call, but otherwise the change to TLS would be transparent,
 * without a need to close an old or open a new file descriptor.
 *
 * Clients would provide the client_hostname and server_hostname,
 * servers would provide just the latter.
 *
 * The callback is provided with the new file descriptor, or
 * -1 with errno set on error.  It is also given the data,
 * which should suffice to reconstruct a byte pointer to the
 * data structure by subtraction of offsetof(struct,field).
 *
 *TODO* This is still blocking due to the TLS Pool API
 *
 *TODO* Can the TLS Pool handle/produce non-blocking sockets?
 *
 * Return true on success, or false with errno set on failure.
 * This coincides with *tlsdata_outvar being non-NULL or NULL.
 */
typedef void (*starttls_cb_fd_t) (void *cbdata, int fd_new);
bool starttls_handshake (int fd_old,
			struct dercursor client_hostname, struct dercursor server_hostname,
			struct starttls_data **tlsdata_outvar,
			starttls_cb_fd_t cb, void *cbdata);


/* While an asynchronous starttls_handshake() is in progress,
 * conditions may come up that call for its retraction.  The
 * imaginable causes are a reset of the TCP connection and a
 * timeout that may have been set in the calling module.
 *
 * This function should never fail.
 */
void starttls_handshake_cancel (struct starttls_data *tlsdata);


/* Close the TLS backend after a handshake has been started
 * and returned true.
 */
void starttls_close (struct starttls_data *tlsdata);


/* Return a reference to the local host name as agreed upon
 * during the TLS handshake.  This is useful in a server.
 * This is quick and lightweight, and it will not fail.
 *
 * This cannot be called before starttls_handshake() is done.
 * TODO: It should still be ok after starttls_*_realm_check_certificate().
 */
struct dercursor starttls_local_hostname_fetch_certificate (struct starttls_data *tlsdata);


/* Return a reference to the remote host name as agreed upon
 * during the TLS handshake.  This is useful in a server.
 * This is quick and lightweight, and it will not fail.
 *
 * This cannot be called before starttls_handshake() is done.
 * TODO: It should still be ok after starttls_*_realm_check_certificate().
 */
struct dercursor starttls_remote_hostname_fetch_certificate (struct starttls_data *tlsdata);


/* Test if the remote peer used the presented host name in its
 * certificate.  This is quick and lightweight, usable in a
 * loop that iterates over SRV records.  There are no errors.
 *
 * This cannot be called before starttls_handshake() is done.
 * TODO: It should still be ok after starttls_*_realm_check_certificate().
 *
 * Return true when the host names match, false otherwise.
 */
bool starttls_remote_hostname_check_certificate (struct dercursor hostname,
				struct starttls_data *tlsdata);


/* Test if the local peer can perform for the realm name, by
 * looking for the realm in the certificate.  This is a little
 * less efficient, but much more failsafe than configuring a
 * list locally (and guessing to what server host names it
 * applies).
 *
 * Internally, the REALM is used like "krbtgt/REALM@REALM" in
 * the usual DER form, so as a SEQUENCE of the REALM and the
 * PrincipalName of name-type TODO:2 and the two strings
 * "krbtgt" and REALM.  This must match exactly with one of
 * the SubjectAlternativeName list elements in the local
 * certificate as presented by the TLS Pool.
 *
 * This cannot be called before starttls_handshake() is done.
 *
 * The callback routine is called with true for success, or
 * false with errno set otherwise.
 *
 * Return true when the callback was successfully initiated,
 * or false with errno set otherwise.
 */
typedef void (*starttls_cb_test_t) (void *cbdata, bool ok);
bool starttls_local_realm_check_certificate (struct dercursor localrealm,
			struct starttls_data *tlsdata,
			starttls_cb_test_t cb, void *cbdata);


/* Test if the remote peer can perform for the realm name
 *
 * Internally, the REALM is used like "krbtgt/REALM@REALM" in
 * the usual DER form, so as a SEQUENCE of the REALM and the
 * PrincipalName of name-type TODO:2 and the two strings
 * "krbtgt" and REALM.  This must match exactly with one of
 * the SubjectAlternativeName list elements in the remote
 * certificate as presented by the TLS Pool.
 *
 * This cannot be called before starttls_handshake() is done.
 *
 * The callback routine is called with true for success, or
 * false with errno set otherwise.
 *
 * Return true when the callback was successfully initiated,
 * or false with errno set otherwise.
 */
bool starttls_remote_realm_check_certificate (struct dercursor remoterealm,
			struct starttls_data *tlsdata,
			starttls_cb_test_t cb, void *cbdata);


/* Ask for a pseudo-random key of the given size, based on
 * RFC 5705, after providing a label and optional context
 * value and, very importantly, the master secret that only
 * the TLS client and server know.  When both perform the
 * same call, they would find the same key.
 *
 * The callback routine is called with true for success, or
 * false with errno set otherwise.
 *
 * Return true when the callback was successfully initiated,
 * or false with errno set otherwise.
 */
bool starttls_export_key (struct dercursor label, struct dercursor opt_ctxval,
			uint16_t size_random, uint8_t *out_random,
			struct starttls_data *tlsdata,
			starttls_cb_test_t cb, void *cbdata);


#endif /* KXOVER_STARTTLS_H */

