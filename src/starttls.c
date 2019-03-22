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


#include "starttls.h"


/* The starttls_data is a structure that is allocated and freed in
 * the code using this module, presumably as part of a larger data
 * structure.  Its internals are not guaranteed to last, as they
 * heavily depend on the TLS mechanism used in the current form of
 * the starttls module, which is a choice from which the calling
 * code is isolated.  Use the API, and nothing but the API.
 */
struct starttls_data {
	struct tlspool_command cmd;
};


/* The file descrpiptor for asynchronous / non-blocking access to
 * the TLS Pool.
 */
static int starttlspool_fd = -1;


/* The event loop that includes the TLS Pool asynchronous events.
 */
static ev_loop starttlspool_loop;


/* The timer for asking the TLS Pool for a file descriptor.  It will
 * manually repeat until successful.
 */
static ev_timer starttlspool_setup_timer;


/* The io event that listens to the starttlspool_fd.
 *
 * When it is setup, it will be monitored for events
 * such as:
 *  - EV_READ  to trigger callbacks for TLS Pool queries
 *  - EV_ERROR to detect shutdown
 */
static ev_io starttlspool_io;


/* This is a callback function to setup a TLS Pool file handle.
 *
 * In terms of libev, an ev_timer is initialised with a repeating
 * time and we will then call ev_timer_again() every time it
 * wants to schedule a future trigger of this setup function.
 * With this strategy, the first call to this function may be
 * made to start the repeated attempts, provided that we are
 * sure that the timer is not active yet.
 */
static void cb_starttlspool_setup (EV_P_ ev_timer *evt, int _revents) {
	static void cb_starttlspool_response (EV_P_ ev_io *evt, int revents);
	/* Connect so that we can turn responses into events */
	starttlspool_fd = tlspool_async_poolfd ();
	if (starttlspool_fd < 0) {
		/* This even works if the timer has already started */
		ev_timer_again (starttlspool_loop, evt);
		return;
	}
	/* Register the connection with the event loop */
	ev_io_init (&starttlspool_io, cb_starttlspool_response,
			starttlspool_fd, EV_READ | EV_ERROR);
	ev_io_start (starttlspool_loop, &starttlspool_io);
}


/* Stop the TLS Pool on a backend file handle.
 */
static void starttlspool_stop (void) {
	assert (starttlspool_fd >= 0);
	/* Decouple the I/O event handler */
	ev_io_stop (&starttlspool_io);
	/* Close the file descriptor */
	close (starttlspool_fd);
	/* Return an error message to all pending requests */
	tlspool_cancel_all (starttlspool_fd);
	/* Allow another round for starttlspool_setup() */
	starttlspool_fd = -1;
}


/* Start the TLS Pool with a backend file handle.  This is done on a
 * timer with callback, which will be asked to fire again upon failure.
 */
static void starttlspool_start (void) {
	assert (starttlspool_fd < 0);
	assert ( !ev_is_active (&starttlspool_setup_timer) );
	ev_timer_init (&starttlspool_setup_timer, starttlspool_setup);
	timer->repeat = 1.0;
	cb_starttlspool_setup (&starttlspool_setup_timer, EV_TIMER);
}


/* This is a callback function to process events from the TLS Pool.
 *
 * In terms of libev, an ev_io is listening to the starttlspool_fd
 * for EV_READ or EV_ERROR.  EV_READ is handled by calling the
 * readout processing function, and EV_ERROR indicates that we
 * should restart the connection to the TLS Pool.
 */
static void cb_starttlspool_response (EV_P_ ev_io *evt, int revents) {
	/* First process reading events, even under an error */
	if (revents & EV_READ) {
		tlspool_process (starttlspool_fd);
	}
	/* On errors, restart the TLS Pool, possibly deferred */
	if (revents & EV_ERROR) {
		starttlspool_stop  ();
		starttlspool_start ()
	}
}

	
/* Initialise the starttls module.  This involves preparation of TLS
 * processing with the TLS Pool through its asynchronous API.
 *
 * Return true on success, or false with kxerrno set on failure.
 */
bool starttls_init (ev_loop *loop) {
	/* Initialise the background timer; deferred so no failure */
	starttlspool_loop = loop;
	starttlspool_start ();
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
 * -1 with kxerrno set on error.  It is also given the data,
 * which should suffice to reconstruct a byte pointer to the
 * data structure by subtraction of offsetof(struct,field).
 *
 *TODO* This is still blocking due to the TLS Pool API
 *
 *TODO* Can the TLS Pool handle/produce non-blocking sockets?
 *
 * Return true on success, or false with kxerrno set on failure.
 * This coincides with *tlsdata_outvar being non-NULL or NULL.
 */
typedef void (*starttls_cb_fd_t) (void *cbdata, int fd_new);
bool starttls_handshake (int fd_old,
			struct dercursor client_hostname, struct dercursor server_hostname,
			struct starttls_data **tlsdata_outvar,
			starttls_cb_fd_t cb, void *cbdata) {
	assert (fd_old >= 0);
	assert ( server_hostname.derptr != NULL);
	assert (*server_hostname.derptr != '\0');
	if (server_hostname.derlen > 127) {
		kxerrno = ERANGE;
		return NULL;
	}
	if (client_hostname.derptr != NULL) && (client_hostname.derlen > 127)) {
		kxerrno = ERANGE;
		return NULL;
	}
	/* Allocate and initialise tlsdata */
	struct starttls_data *tlsdata = calloc (1, sizeof (struct starttls_data));
	*tlsdata_outvar = tlsdata;
	if (tlsdata == NULL) {
		kxerrno = ENOMEM;
		return false;
	}
	//TODO// Initialise tlsdata: localid, remoteid, flags, command, ...
	memset (tlsdata.pioc_starttls.localid,  ...WHICH...);
	memset (tlsdata.pioc_starttls.remoteid, ...WHICH...);
	//TODO// Make this asynchronous and non-blocking!
	fd_new = tlspool_starttls (fd_old, &tlsdata->cmd.pioc_starttls, NULL);
	if (fd_new >= 0) {
		/* The handshake succeeded */
		cb (cbdata, fd_new);
		return true;
	} else {
		/* The handshake failed, errno comes from TLS Pool */
		kxerrno = errno;
		cb (cbdata, -1);
		free (tlsdata);
		*tlsdata_outvar = NULL;
		return false;
	}
}


/* While an asynchronous starttls_handshake() is in progress,
 * conditions may come up that call for its retraction.  The
 * imaginable causes are a reset of the TCP connection and a
 * timeout that may have been set in the calling module.
 *
 * This function should never fail.
 */
void starttls_handshake_cancel (struct starttls_data *tlsdata) {
	//TODO// Once non-blocking, some code will be necessary
	;
}


/* Close the TLS backend after a handshake has been started
 * and returned true.
 */
void starttls_close (struct starttls_data *tlsdata) {
	//TODO// Possibly cleanup pending work, needed once non-blocking
	free (tlsdata);
}


/* Return a reference to the local host name as agreed upon
 * during the TLS handshake.  This is useful in a server.
 * This is quick and lightweight, and it will not fail.
 *
 * This cannot be called before starttls_handshake() is done.
 * TODO: It should still be ok after starttls_*_realm_check_certificate().
 */
struct dercursor starttls_local_hostname_fetch_certificate (struct starttls_data *tlsdata) {
	struct dercursor hostname;
	char *localid = tlsdata->localid;
	hostname->derptr = localid;
	hostname->derlen = strnlen (localid, 127);
	return hostname;
}


/* Return a reference to the remote host name as agreed upon
 * during the TLS handshake.  This is useful in a server.
 * This is quick and lightweight, and it will not fail.
 *
 * This cannot be called before starttls_handshake() is done.
 * TODO: It should still be ok after starttls_*_realm_check_certificate().
 */
struct dercursor starttls_remote_hostname_fetch_certificate (struct starttls_data *tlsdata) {
	struct dercursor hostname;
	char *remoteid = tlsdata->remoteid;
	hostname->derptr = remoteid;
	hostname->derlen = strnlen (remoteid, 127);
	return hostname;
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
#define member_size(type,field) (sizeof(((type *)0)->field))
bool starttls_remote_hostname_check_certificate (struct dercursor hostname,
				struct starttls_data *tlsdata) {
	/* Names longer than the TLS Pool can present will not match */
	if (hostname.derlen >= member_size (struct starttls_data, remoteid)) {
		return false;
	}
	/* Compare the bytes and the length */
	char *remoteid = tlsdata->remoteid;
	if (strncasecmp (remoteid, hostname.derptr, hostname.derlen) != 0) {
		return false;
	}
	if (remoteid [hostname.derlen] != '\0') {
		return false;
	}
	/* Neither disturbances nor differences found */
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
 * false with kxerrno set otherwise.
 *
 * Return true when the callback was successfully initiated,
 * or false with kxerrno set otherwise.
 */
typedef void (*starttls_cb_test) (void *cbdata, bool ok);
bool starttls_local_realm_check_certificate (struct dercursor localrealm,
			struct starttls_data *tlsdata,
			starttls_cb_test_t cb, void *cbdata) {
	//TODO// Implement this with a new async call to the TLS Pool
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
 * false with kxerrno set otherwise.
 *
 * Return true when the callback was successfully initiated,
 * or false with kxerrno set otherwise.
 */
bool starttls_remote_realm_check_certificate (struct dercursor remoterealm,
			struct starttls_data *tlsdata,
			starttls_cb_test_t cb, void *cbdata) {
	//TODO// Implement this with a new async call to the TLS Pool
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
 * false with kxerrno set otherwise.
 *
 * Return true when the callback was successfully initiated,
 * or false with kxerrno set otherwise.
 */
bool starttls_export_key (struct dercursor label, struct dercursor opt_ctxval,
			uint16_t size_random, uint8_t *out_random,
			struct starttls_data *tlsdata;
			starttls_cb_test_t cb, void *cbdata) {
	/* Prepare the zero-terminated variables expected by the TLS Pool */
	//TODO// This is a weakness in the TLS Pool API, use ptr/len there too!!!
	char label0 [label.derlen+1];
	memcpy (label0, label.derptr, label.derlen);
	label0 [label.derlen] = '\0';
	char ctxval0 [opt_ctxval.derlen+1];
	memcpy (ctxval0, opt_ctxval.derptr, opt_ctxval.derlen);
	ctxval0 [opt_ctxval.derlen] = '\0';
	char *ctxval0_opt = der_isnonempty (opt_ctxval) ? &ctxval0 : NULL;
	/* Invoke the key exporter of the TLS Pool -- TODO: MAKE ASYNC */
	if (tlspool_prng (label, ctxval0_opt, size_random, out_random, tlsdata.ctlkey) != 0) {
		cb (cbdata, false);
	} else {
		cb (cbdata, true);
	}
	/* Return success in setting up the asynchronous call */
	return true;
}


