/* Fake TLS module -- run over plain TCP and claim OK on any tests.
 *
 * This module is NOT FIT FOR PRODUCTION.  It is only here to ease
 * development, debugging and perhaps testing.  For any other use,
 * expect this code to lie, cheat and bedevil you.  Other than that,
 * it is a stub replacement for starttls.c, implementing the same
 * API calls.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include "starttls.h"



/* Empty data structure */
struct starttls_data { };


	
/* Initialise the starttls module.  This involves preparation of TLS
 * processing with the TLS Pool through its asynchronous API.
 *
 * Return true on success, or false with errno set on failure.
 */
bool starttls_init (EV_P) {
	return true;
}


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
			starttls_t **tlsdata_outvar,
			starttls_cb_fd_t cb, void *cbdata) {
	cb (cbdata, fd_old);
	return true;
}


/* While an asynchronous starttls_handshake() is in progress,
 * conditions may come up that call for its retraction.  The
 * imaginable causes are a reset of the TCP connection and a
 * timeout that may have been set in the calling module.
 *
 * This function should never fail.
 */
void starttls_handshake_cancel (struct starttls_data *tlsdata) {
	;
}


/* Close the TLS backend after a handshake has been started
 * and returned true.
 */
void starttls_close (struct starttls_data *tlsdata) {
	;
}


/* Return a reference to the local host name as agreed upon
 * during the TLS handshake.  This is useful in a server.
 * This is quick and lightweight, and it will not fail.
 *
 * This cannot be called before starttls_handshake() is done.
 * TODO: It should still be ok after starttls_*_realm_check_certificate().
 */
struct dercursor starttls_local_hostname_fetch_certificate (struct starttls_data *tlsdata) {
	struct dercursor retval = {
		.derptr = "localhost",
		.derlen = 9
	};
	return retval;
}


/* Return a reference to the remote host name as agreed upon
 * during the TLS handshake.  This is useful in a server.
 * This is quick and lightweight, and it will not fail.
 *
 * This cannot be called before starttls_handshake() is done.
 * TODO: It should still be ok after starttls_*_realm_check_certificate().
 */
struct dercursor starttls_remote_hostname_fetch_certificate (struct starttls_data *tlsdata) {
	struct dercursor retval = {
		.derptr = "localhost",
		9
	};
	return retval;
}


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
				struct starttls_data *tlsdata) {
	return true;
}


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
			starttls_cb_test_t cb, void *cbdata) {
	cb (cbdata, true);
	return true;
}


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
			starttls_cb_test_t cb, void *cbdata) {
	cb (cbdata, true);
	return true;
}


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
			starttls_t *tlsdata,
			starttls_cb_test_t cb, void *cbdata) {
	cb (cbdata, true);
	return true;
}


