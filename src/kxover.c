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


#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <unistd.h>

#include <unbound.h>

#include <quick-der/api.h>
#include <quick-der/rfc4120.h>


/* The maximum number of bytes in a DERific Kerberos message */
#define MAXLEN_KERBEROS 1500


/* Application tags used in Kerberos with KXOVER extensions */
#define APPTAG_KRB_ERROR  ( 0x40 | 0x20 | 30 )
#define APPTAG_KXOVER_REQ ( 0x40 | 0x20 | 18 )
#define APPTAG_KXOVER_REP ( 0x40 | 0x20 | 19 )


/* Quick DER path to walk into a KRB-ERROR (whose der_header has
 * already been analysed and skipped) and find the error-code.
 */
static const derwalk krberror2code [] = {
	DER_WALK_ENTER | DER_SEQUENCE,         // SEQUENCE { ... }
	DER_WALK_SKIP  | DER_INTEGER,          // kvno 5
	DER_WALK_SKIP  | DER_INTEGER,          // msg-type 30
	DER_WALK_OPTIONAL,
	DER_WALK_SKIP  | DER_GENERALIZEDTIME,  // ctime
	DER_WALK_OPTIONAL,
	DER_WALK_SKIP  | DER_INTEGER,          // cusec
	DER_WALK_SKIP  | DER_GENERALIZEDTIME,  // stime
	DER_WALK_SKIP  | DER_INTEGER,          // susec
	DER_WALK_ENTER | DER_INTEGER,          // error-code
	DER_WALK_END
};



/* Quick DER pack/unpack instructions for KRB-ERROR.
 */
static const derwalk pack_KRB_ERROR [] = { DER_PACK_rfc4120_KRB_ERROR, DER_PACK_END };
typedef DER_OVLY_rfc4120_KRB_ERROR ovly_KRB_ERROR;


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
 * to the caller.  Success is reported with errno being zero.
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
			int errno,
			dercrs client_realm,
			dercrs service_realm);


/* The states that a KXOVER action can be in; this includes
 * being a client or a server, whose states are completely
 * separate, until they reach their final state in which
 * only success/error reporting and cleanup remains.
 */
enum kxover_state {
	//
	// States for both KX Client and KX Server
	KXS_UNDEFINED = 0,	/* Birth, but not live state */
	KXS_FINISHED,		/* Finished, see last_errno for ok/ko */
	KXS_CALLBACK,		/* Currently processing the callback */
	KXS_CLEANUP,		/* Cleaning up, or ready for doing so */
	//
	//
	// KX Client states (includes setup of TCP and STARTTLS)
	KXS_CLIENT_PRE,		/* Code before any client state */
	KXS_CLIENT_INITIALISED,	/* Client has been initialised */
	KXS_CLIENT_DNSSEC_REALM,/* In DNSSEC query _kerberos TXT */
	KXS_CLIENT_DNSSEC_KDC,	/* In DNSSEC query _kerberos-tls._tcp SRV */
	KXS_CLIENT_DNS_AAAA_A,	/* Iterate SRV, find AAAA/A records */
	KXS_CLIENT_CONNECTING,	/* Iterate AAAA/A, connect to KXOVER server */
	KXS_CLIENT_STARTTLS,	/* Sent STARTTLS to KXOVER server, await reply */
	KXS_CLIENT_HANDSHAKE,	/* Asked STARTTLS module to shake hands */
	KXS_CLIENT_REALMSCHECK,	/* Checking both realms against TLS certs */
	KXS_CLIENT_REALM2CHECK,	/* Checking 2nd  realm  against TLS certs */
	KXS_CLIENT_KX_SENT,	/* Sent KX-OFFER to KXOVER server */
	KXS_CLIENT_KX_RECEIVED,	/* Received KX-OFFER from KXOVER server */
	// KXS_CLIENT_KX_CHECKS,	/* Checking if the KX-OFFERs match */
	KXS_CLIENT_KEY_STORING,	/* Key construction and storage for the KDC */
				/* ...then on to KXS_SUCCESS */
	KXS_CLIENT_POST,	/* Code after any client state */
	//
	// KX Server states (already has TCP and STARTTLS)
	KXS_SERVER_PRE,		/* Code before any server state */
	KXS_SERVER_INITIALISED,	/* Server has been initialised */
	KXS_SERVER_KX_RECEIVED,	/* Received KX-OFFER from KXOVER client */
	KXS_SERVER_REALMSCHECK,	/* Checking both realms against TLS certs */
	KXS_SERVER_REALM2CHECK,	/* Checking 2nd  realm  against TLS certs */
	KXS_SERVER_DNSSEC_KDC,	/* In DNSSEC query _kerberos-tls._tcp SRV */
	// KXS_SERVER_HOSTCHECK,	/* Iterate SRV, compare to TLS client host */
	KXS_SERVER_KEY_STORING,	/* Key construction and storage for the KDC */
	KXS_SERVER_KX_SENT,	/* Sent KX-OFFER back to KXOVER client */
				/* ...then on to KXS_SUCCESS */
	KXS_SERVER_POST,	/* Code after any server state */
};


/* The structure for management of KXOVER progress.
 * This is an abstract data pointer for other modules.
 * It holds (internal) event handlers as well as the
 * callback information to report overall success or
 * failure.
 */
struct kxover_data {
	enum kxover_state progress;
	int last_errno;
	cb_kxover_result *cb;
	void *cbdata;
	derptr crealm;
	derptr srealm;
	derptr kx_req;
	derptr kx_rep;
	int kxoffer_fd;
	char *kerberos_tls_hostname;
	struct ub_result *ubres_txt;
	struct ub_result *ubres_srv;
	struct ub_result *ubres_aaaa;
	struct ub_result *ubres_a;
	int ubqid_txt;
	int ubqid_srv;
	int ubqid_aaaa;
	int ubqid_a;
	ev_io ev_clicnx;
} kxover_t;


/* Iterators can try a number of values in a sequence,
 * until one is found to be satisfactory.  There can even
 * be nested iterators.
 *
 * We shall need to iterate over DNS records and have an
 * (asynchronous) test at the end, such as a name match
 * or a socket connection attempt.
 *
 * The variables have the following meanings:
 *  - cursor is the current index in ub_result->data
 *  - started is set when the iteration has started
 *  - stopped is set when the iteration has finished
 */
struct iterator {
	int cursor;
	uint16_t current;
	uint16_t prepare;
	bool started;
	bool stopped;
}


/* Reset an iterator.  This may be done initially or when
 * the need arises to start again.  The routine is generic.
 */
void iter_reset (struct iterator *it) {
	// it->cursor  = 0;
	// it->current = 0;
	// it->prepare = 0;
	// it->started = false;
	// it->stopped = false;
	memset (it, 0, sizeof (it));
}


/* The event loop for KXOVER operations.
 */
static ev_loop kxover_loop;


/* The Unbound library context for KXOVER lookups.
 */
static struct ub_ctx kxover_unbound_ctx = NULL;


/* The Unbound library watcher, to trigger _cb_kxover_unbound().
 */
static ev_io kxover_unbound_watcher;


/* DER-encoded data:
 *  - der_notfound should be in the KRB-ERROR error-code for NOTFOUND.
 *  - der_int_5 & der_int_30 encode integers 5 and 30.
 *  - der_kstr_krbtgt encodes the "krbtgt" as KerberosString.
 */
static const uint8_t der_notfound    [] = { 0x07 };
static const uint8_t der_int_5       [] = { 0x02, 0x01, 5 };
static const uint8_t der_int_30      [] = { 0x02, 0x01, 30 };
static const uint8_t der_kstr_krbtgt [] = { 'k', 'r', 'b', 't', 'g', 't' };
static const dercursor dercrs_notfound     = { der_notfound,    sizeof(der_notfound   ) };
static const dercursor dercrs_int_5        = { der_int_5,       sizeof(der_int_5      ) };
static const dercursor dercrs_int_30       = { der_int_30,      sizeof(der_int_30     ) };
static const dercursor dercrs_kstr_krbtgt  = { der_kstr_krbtgt, sizeof(der_kstr_krbtgt) };


/* SRV iterators pass through the same records more than once, with
 * ever-rising priority in it->current.  While passing through, the
 * next priority level is collected in it->prepare, which will end
 * with the next higher priority level, unless none exists, in which
 * case it ends up equal to it->current.
 *
 * The iterator ends with it->cursor numbering the current element;
 * with it->started set if the cursor has been run at least once;
 * with it->stopped set when nothing more can be done.
 */
bool iter_srv_next (struct iterator *it, struct ub_result *result) {
	/* See if we need to start the iterator */
	if (!it->started) {
		it->started = true;
		it->stopped = false;
		it->cursor = -1;
	}
	/* Increment the cursor, ordered by rising priority and occurrence */
	do {
		/* Move the cursor forward */
		it->cursor++;
		/* Handle skipping beyond the last entry */
		if (result->data [it->cursor] == NULL) {
			if (it->prepare > it->current) {
				/* If we recycle, we will find more */
				it->current = it->prepare;
				it->cursor = -1;
				continue;
			} else {
				/* We have done all we can */
				it->stopped = true;
				continue;
			}
		} else {
			/* Skip very short host names, including "." */
			if (result->len [it->cursor] < 6+3) {
				continue;
			}
			/* Prepare the priority level for the next round */
			uint16_t crslvl = ntohs (* (uint16_t *) result->data [it->cursor]);
			if (it->prepare == it->current) {
				it->prepare = crslvl;
			} else {
				if ((crslvl < it->prepare) && (crslvl > it->current)) {
					it->prepare = crslvl;
				}
			}
			/* We (currently) ignore the weight -- sorry :) */
			/* See if the cursor points to a usable position */
			if (crslvl == it->current) {
				/* It's a new one, and its level is right! */
				return true;
			}
		}
	} while (!it->stopped);
	return false;
}


/* Process incoming AAAA and A records with addresses to
 * connect to from the KXOVER client.  Both types of address
 * must have arrived before the iteration over addresses
 * commences.
 */
static void cb_kxs_client_dns_aaaa_a (
			struct kxover_data *kxd,
			int err, struct ub_result *result) {
	/* Load the results of AAAA and A queries in any order of arrival */
	if (result->qtype == DNS_AAAA) {
		assert (kxd->ubres_aaaa == NULL);
		kxd->ubres_aaaa = result;
	} else if (result->qtype == DNS_A) {
		assert (kxd->ubres_a == NULL);
		kxd->ubres_a = result;
	} else {
		/* Bound to fail; no need to also add DNS_A */
		assert (result->qtype == DNS_AAAA);
	}
	/* Only continue processing after then 2nd result */
	if ((kxd->ubres_aaaa == NULL) || (kxd->ubres_a == NULL)) {
		return;
	}
	/* Perform santity checks and administration on both AAAA and A */
	static struct kx_ub_constraints proper_aaaa = {
		.qprefix          = "",
		.rrtype           = DNS_AAAA,
		.progress_pre     = KXS_CLIENT_DNS_AAAA_A,
		.require_dnssec   = false,
		.require_0_1_many = -1,
		.result_offset    = offsetof (struct kxover_data, ubres_aaaa),
		.cancel_offset    = offsetof (struct kxover_data, ubqid_aaaa),
	};
	if (!_kxover_unbound_proper (kxd, &proper_aaaa, err, result)) {
		kxd->last_errno = 
		goto bailout;
	}
	static struct kx_ub_constraints proper_a = {
		.qprefix          = "",
		.rrtype           = DNS_A,
		.progress_pre     = KXS_CLIENT_DNS_AAAA_A,
		.require_dnssec   = false,
		.require_0_1_many = -1,
		.result_offset    = offsetof (struct kxover_data, ubres_a),
		.cancel_offset    = offsetof (struct kxover_data, ubqid_a),
	};
	if (!_kxover_unbound_proper (kxd, &proper_a, err, result)) {
		kxd->last_errno = 
		goto bailout;
	}
	/* Reset the iterator for AAAA and A; initiate connection attempts */
	iter_reset (&kxd->iter_aaaa_a);
	kxover_client_connect_attempt ();
	return;
bailout:
	kxover_finish (kxd);
}


/* Resolve a hostname into AAAA and A records.  The queries are run
 * together, and end in the same callback, which acts after the second
 * has arrived.  This is only done for the client.
 */
static void kx_resolve_aaaa_a (struct kxover_data *kxd) {
	/* Free any prior results; these will then have succeeded */
	if (kxd->ubres_aaaa != NULL) {
		ub_resolve_free (kxd->ubres_aaaa);
		kxd->ubres_aaaa = NULL;
	}
	if (kxd->ubres_a != NULL) {
		ub_resolve_free (kxd->ubres_a);
		kxd->ubres_a = NULL;
	}
	/* Start two queries, one for AAAA and one for A */
	bool ok6 = ub_resolve_async (kxover_unbound_ctx,
			kerberos_tls_hostname, DNS_AAAA, DNS_INET,
			kxd, cb_kxs_client_dns_aaaa_a, &kxd->ubqid_srv);
	bool ok4 = ub_resolve_async (kxover_unbound_ctx,
			kerberos_tls_hostname, DNS_A   , DNS_INET,
			kxd, cb_kxs_client_dns_aaaa_a, &kxd->ubqid_srv);
	/* If only one got started, cancel the whole batch */
	if (ok4 != ok6) {
		ub_cancel (kxover_unbound_ctx,
				ok4 ? kxd->ubqid_a : kxd->ubqid_aaaa);
		kxd->errno = 
		goto bailout;
	}
	/* Update the state and await progress */
	kxd->progress = KXS_CLIENT_DNS_AAAA_A;
	return;
bailout:
	kxover_finish (kxd);
}


/* Iterate over AAAA and A records.  We shall use positive cursors 0,1,...
 * for AAAA and negative -1,-2,... for A records.  This allows us to
 * have one iterator working on two sets of answers.  Iteration starts
 * with IPv6, of course.
 */
bool iter_aaaa_a_next (struct iterator *it, struct ub_result *aaaa, struct ub_result *a) {
	/* Compute a preliminary next cursor value */
	if (!it->started) {
		it->cursor = 0;
		it->started = true;
		it->stopped = false;
	} else if (it->cursor >= 0) {
		it->cursor++;
	} else {
		it->cursor--;
	}
	/* Test positive values against AAAA records */
	if (it->cursor >= 0) {
		if (aaaa->havedata && (aaaa->data [it->cursor] != NULL)) {
			/* The cursor points to a good AAAA answer */
			return true;
		} else {
			/* The cursor points beyond the last record */
			it->cursor = -1;
		}
	}
	/* Test negative values against A records */
	if (it->cursor < 0) {
		if (a->havedata && (a->data [-1-it->cursor] != NULL)) {
			/* The cursor points to a good A answer */
			return true;
		} else {
			it->stopped = true;
		}
	}
	/* We failed and will stop now */
	return false;
}


/* Make a connection attempt to the AAAA/A host at the SRV port.
 *
 * This function can be called over and over again, when connect()
 * fails.  It will iterate over SRV and AAAA/A records until the
 * options are exhausted.
 *
 * This is an asynchronous attempt, that is, it uses non-blocking
 * sockets with connect() and awaits EV_READ | EV_WRITE | EV_ERROR.
 */
void kxover_client_connect_attempt (struct kxover_data *kxd) {
	int sox = -1;
	/* Prepare SRV iteration; not stopped but started */
	if (!kxd->iter_srv.started) {
		iter_srv_next (&kxd->iter_srv, kxd->ubres_srv);
	}
	if (kxd->iter_srv.stopped) {
		kxd->last_errno = 
		goto bailout;
	}
	/* Move AAAA/A forward, possibly to the first entry */
	bool done = false;
	iter_aaaa_a_next (&kxd->iter_aaaa_a, kxd->ubres_aaaa, kxd->ubres_a);
	if (kxd->iter_aaaa_a.stopped) {
		if (iter_srv_next (&kxd->iter_srv, kxd->ubres_srv)) {
			/* Resolve the SRV host's AAAA and A records and call again */
			goto resolve;
		} else {
			/* No more options left, bail out */
			kxd->last_errno = 
			goto bailout;
		}
	}
	/* Create a socket to connect over TCP */
	int adrfam = (kxd->iter_aaaa_a >= 0) ? AF_INET6 : AF_INET;
	sox = socket (adrfam, SOCK_STREAM, 0);
	if (sox < 0) {
		kxd->last_errno = errno;
		goto bailout;
	}
	/* Set the socket to non-blocking mode */
	int soxflags = fcntl (sox, F_GETFL, 0);
	if (fcntl (sox, F_SETFL, soxflags | O_NONBLOCK) != 0) {
		kxd->last_errno = errno;
		goto bailout;
	}
	/* Fill a socket address: sa/salen */
	struct sockaddr sa;
	memset (&sa, 0, sizeof (sa));
	sa.sa_family = adrfam;
	socklen_t salen;
	uint16_t port_net_order = ((uint16_t *) kxd->ubres_srv->data [kxd->iter_srv.cursor]) [2];
	if (adrfam == AF_INET6) {
		struct sockaddr_in6 *sin6 = &sa;
		salen = sizeof (*sin6);
		memcpy (sin6.sin6_addr,
			kxd->ubres_aaaa->data [kxd->iter_aaaa_a.cursor],
			16);
		sin6.sin6_port = port_net_order;
	} else {
		struct sockaddr_in *sin = &sa;
		salen = sizeof (*sin);
		memcpy (sin.sin_addr,
			kxd->ubres_aaaa->data [-1-kxd->iter_aaaa_a.cursor],
			4);
		sin.sin_port = port_net_order;
	}
	/* Setup event handling with a connect() responder as callback */
	ev_io_init (&kxd->ev_clicnx, cb_kxs_client_connecting, sox, EV_WRITE | EV_ERROR);
	ev_io_start (kxover_loop, &kxd->ev_clicnx);
	/* Finally connect to the remote's AAAA/A and the port from SRV */
	if (connect (sox, &sa, salen) < 0) {
		/* Some values in errno are caused by the deferral */
		if ((errno != EINPROGRESS) && (errno != EWOULDBLOCK) && (errno != EAGAIN)) {
			kxd->last_errno =
			goto bailout;
		}
	}
	/* The connect() is in progress, done for now */
	kxd->kxoffer_fd = sox;
	kxd->progress = KXS_CLIENT_CONNECTING;
	return;
resolve:
	/* Need to lookup AAAA and A records first */
	kx_resolve_aaaa_a (kxd);
	return;
bailout:
	/* Handle errors by reporting failure to the KXOVER caller */
	if (sox >= 0) {
		close (sox);
	}
	kxover_finish ();
	return;
}


/* Asynchronous attempts to connect to an AAAA or A address with an
 * SRV port will end up here, reporting whether the connection was
 * setup as expected.  If so, continue with the first data send;
 * in case of failure, iterate back to the AAAA/A loop, and perhaps
 * even back to the SRV loop surrounding that.
 */
static void cb_kxs_client_connecting (EV_P_ ev_io *evt, int revents) {
	struct kxover_data *kxd =
		(struct kxover_data *) (
			((uint8_t *) evt) -
				offsetof (struct kxover_data, ev_clicnx));
	ev_io_stop (&kxd->ev_clicnx);
	/* On failure, try again on any further addresses */
	if (revents & EV_ERROR) {
		kxover_client_connect_attempt (kxd);
		return;
	}
	/* Once we are connected, we switch the socket to reading mode */
	ev_io_init (&kxd->ev_clicnx, cb_kxs_client_starttls,
			kxd->kxoffer_fd, EV_READ | EV_ERROR);
	ev_loop (kxover_loop, &kxd->ev_clicnx);
	//TODO// Use another callback function, or set progress?
	/* Send the STARTTLS flag */
	uint8_t buf4 [4];
	* (uint32_t *) buf4 = htonl (0x80000001);
	if (write (kxd->kxoffer_fd, buf4, 4) != 4) {
		/* Close the socket and let event handler signal it */
		close (kxd->kxoffer_fd);
		kxd->kxoffer_fd = -1;
		return;
	}
	/* Continue waiting for the STARTTLS response */
	kxd->progress = KXS_CLIENT_STARTTLS;
}


/* After having sent the STARTTLS extension to the connected socket,
 * we wait for this callback stating that something can be read.
 * We require that all four bytes are available at this time, and
 * check that it coincides with our expectations.  If so, we move
 * on to the TLS handshake via the starttls.c module; otherwise, we
 * bail out on the client role (we do not try other addresses).
 */
static void cb_kxs_client_starttls (EV_P_ ev_io *evt, int revents) {
	struct kxover_data *kxd =
		(struct kxover_data *) (
			((uint8_t *) evt) -
				offsetof (struct kxover_data, ev_clicnx));
	/* Bail out when socket errors occurred */
	if (revents & EV_ERROR) {
		kxd->last_errno = 
		goto bailout;
	}
	/* Read the STARTTLS reply and check it is what we need */
	uint8_t ist4 [4];
	static uint8_t soll4 [4] = { 0x80, 0x00, 0x00, 0x01 };
	if (read (kxd->kxoffer_fd, ist4, 4) != 4) {
		kxd->last_errno = 
		goto bailout;
	}
	if (memcmp (ist4, soll4, 4) != 0) {
		kxd->last_errno = 
		goto bailout;
	}
	/* Both sides are now ready for TLS, so proceed */
	if (!starttls_handshake (kxd->kxoffer_fd,
			TODO_client_hostname,
			kxd->ubres_srv->data [kxd->iter_srv.cursor];
			&kxd->tlsdata,
			cb_kxs_client_handshake, kxd)) {
		kxd->last_errno = errno;
		goto bailout;
	}
	kxd->progress = KXS_CLIENT_HANDSHAKE;
	return;
bailout:
	kxover_finish ();
}


/* The starttls.c module has reached a verdict on the TLS handshake.
 * This is reflected in fd_new, which is <0 on error or >=0 on success.
 * When failed, we do not try elsewhere, but fail the client attempt.
 */
void cb_kxs_client_handshake (struct kxover_data *kxd, int fd_new) {
	/* Test if the TLS handshake succeeded */
	if (fd_new < 0) {
		goto bailout;
	}
	/* Initiate checks for both realm names by starttls.c */
	bool r_ok = starttls_remote_realm_check_certificate (
			kxd->srealm,
			kxd->tlsdata,
			cb_kxs_client_realmscheck, kxd);
	bool l_ok = starttls_local_realm_check_certificate (
			kxd->crealm,
			kxd->tlsdata,
			cb_kxs_client_realmscheck, kxd);
	/* Both sides must be checked, otherwise cancel */
	if (r_ok != l_ok) {
		starttls_cancel (...TODO...);
		goto bailout;
	}
	/* Continue into realm checking */
	kxd->progress = KXS_CLIENT_REALMSCHECK;
	return;
bailout:
	kxover_finish ();
}


/* The starttls.c module calls back whether each realm is mentioned
 * in the certificate at the same side of the TLS connection.
 */
void cb_kxs_client_realmscheck (struct kxover_data *kxd, bool success) {
	/* Ensure success */
	if (!success) {
		kxd->last_errno = EACCES;
		goto bailout;
	}
	/* Hold off activity during the first callback (of two) */
	if (kxd->progress == KXS_CLIENT_REALMSCHECK) {
		/* Change progress to "seen one, one more to come" */
		kxd->progress = KXS_CLIENT_REALM2CHECK;
	}
	//TODO// The assertion fails with current trivial realms checks in starttls.c
	assert (kxd->progress == KXS_CLIENT_REALM2CHECK);
	/* Given correct realms on both sides, continue sending KX-OFFER */
	kxover_client_send_offer (kxd);
	return;
bailout:
	kxover_finish ();
}


/* Construct a KX-OFFER from the client to the server, and wait
 * for the corresponding KX-OFFER being returned.
 */
void kxover_client_send_offer (struct kxover_data *kxd) {
	TODO:IMPLEMENT:FROMHERE
}


/* Process an Unbound callback, presumably in response to
 * a query that we posted from here.  We delegate control
 * to Unbound's processor, which will deliver via query
 * callbacks.
 */
static void _cb_kxover_unbound (EV_P_ ev_io *_evt, int _revents) {
	ub_process (kxover_unbound_ctx);
}


/* Initialise the kxover.c module, setting the event loop it
 * should use.
 *
 * (If we decide to set a fixed KDC hostname, this is where.)
 *
 * Return true on succes, or false with errno set on failure.
 */
bool kxover_init (ev_loop *loop, char *dnssec_rootkey_file) {
	assert (kxover_unbound_ctx == NULL);
	kxover_unbound_ctx = ub_ctx_create ();
	if (kxover_unbound_ctx == NULL) {
		errno = ECONNREFUSED;
		return false;
	}
	if (ub_ctx_add_ta_autr (kxover_unbound_ctx, dnssec_rootkey_file)) {
		errno = ECONNREFUSED;
		goto teardown_unbound;
	}
	int fd = ub_fd (kxover_unbound_ctx);
	if (fd < 0) {
		/* Not sure if libunbound sets errno */
		errno = ECONNREFUSED;
		goto teardown_unbound;
	}
	/* Initialise the event loop, with Unbound service */
	kxover_loop = loop;
	ev_io_init (&kxover_unbound_watcher, _cb_kxover_unbound, fd, EV_READ);
	ev_io_start (loop, &kxover_unbound_watcher);
	return true;
teardown_unbound:
	ub_ctx_delete (kxover_unbound_ctx);
	kxover_unbound_ctx = NULL;
	return false;
}


/* Having classified a frame from upstream as Kerberos,
 * interpret the read Kerberos data and see if it should be
 * handled as KXOVER, or passed to the downstream.
 *
 * This function always returns a meaningful result.
 * Possible return values are TCPKRB5_PASS, _KXOVER_REQ as
 * well as _ERROR.
 */
tcpkrb5_t kxover_classify_kerberos_down (derptr krb) {
	uint8_t tag;
	size_t intlen;
	uint8_t hdrlen;
	if (der_header (&krb, &tag, &intlen, &hdrlen) != 0) {
		return TCPKRB5_ERROR;
	}
	if (hdrlen + intlen != krblen) {
		return TCPKRB5_ERROR;
	}
	switch (tag) {
	case APPTAG_KXOVER_REQ:
		return TCPKRB5_KXOVER_REQ;
	case APPTAG_KXOVER_REP:
		return TCPKRB5_ERROR;
	case APPTAG_KRB_ERROR:
	default:
		return TCPKRB5_PASS;
	}
}


/* Having classified a frame from downstream as Kerberos,
 * interpret the read Kerberos data and see if it should be
 * handled locally, or passed to the downstream.
 *
 * This function always returns a meaningful result.
 * Possible return values are TCPKRB5_PASS, _NOTFOUND
 * and _KXOVER_REP as well as _ERROR.
 */
tcpkrb5_t kxover_classify_kerberos_up (derptr krb) {
	uint8_t tag;
	size_t intlen;
	uint8_t hdrlen;
	if (der_header (&krb, &tag, &intlen, &hdrlen) != 0) {
		return TCPKRB5_ERROR;
	}
	if (hdrlen + intlen != krblen) {
		return TCPKRB5_ERROR;
	}
	switch (tag) {
	case APPTAG_KRB_ERROR:
		if (der_walk (krb, krberror2code) != 0) {
			return TCPKRB5_ERROR;
		}
		if (der_cmp (krb, dercrs_notfound) == 0) {
			/* This is a KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN error */
			return TCPKRB5_NOTFOUND;
		} else {
			/* Other KRB5KDC_ERR_ should pass without change */
			return TCPKRB5_PASS;
		}
	case APPTAG_KXOVER_REQ:
		return TCPKRB5_ERROR;
	case APPTAG_KXOVER_REP:
		return TCPKRB5_KXOVER_REP;
	default:
		return TCPKRB5_PASS;
	}
}


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
 *
 * This functions starts the KXOVER server process,
 * and returns an opaque object on success, or NULL
 * with errno set otherwise.  When an object is
 * returned, the callback function will be called to
 * report the overall success or failure of the
 * KXOVER operation.
 */
struct kxover_data *kxover_server (cb_kxover_server cb, void *cbdata,
			derptr kx_req, int kxoffer_fd) {
	assert (reqptr != NULL);
	assert (reqlen > 10);
	assert (kxoffer_fd >= 0);
	/* Allocate and initialise the kxover_data */
	struct kxover_data *kxd;
	kxd = calloc (1, sizeof (struct kxover_data));
	if (kxd == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	kxd->kxoffer_fd = kxoffer_fd;
	kxd->kx_req = kx_req;
	kxd->cb = cb;
	kxd->cbdata = cbdata;
	kxd->progress = KXS_SERVER_INITIALISED;
	return kxd;
}


/* The internal _kxover_server_cleanup() operation checks all
 * fields initialised during kxover_server() and frees any
 * underlying resources.
 */
static void _kxover_server_cleanup (struct kxover_data *kxd) {
	//TODO// Stop event watchers, cleanup
	;
}


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
 * with errno set otherwise.  When an object is
 * returned, the callback function will be called to
 * report the overall success or failure of the
 * KXOVER operation.
 */
struct kxover_data *kxover_client (cb_kxover_server cb, void *cbdata,
			derptr client_realm, derptr service_realm) {
	/* Allocate and initialise the kxover_data */
	struct kxover_data *kxd = NULL;
	char *kerberos_REALM = NULL;
	kxd = calloc (1, sizeof (struct kxover_data));
	if (kxd == NULL) {
		errno = ENOMEM;
		goto bailout;
	}
	kxd->kxoffer_fd = -1;
	kxd->crealm = client_realm;
	kxd->srealm = service_realm;
	kxd->cb = cb;
	kxd->cbdata = cbdata;
	kxd->progress = KXS_CLIENT_INITIALISED;
	/* Initiate activity with a lookup of the realm with _kerberos TXT */
	kerberos_REALM = malloc (10 + service_realm.derlen + 1);
	if (kerberos_REALM == NULL) {
		errno = ENOMEM;
		goto bailout;
	}
	memcpy (kerberos_REALM     , "_kerberos.", 10);
	memcpy (kerberos_REALM + 10, client_realm.derptr, client_realm.derlen)
	kerberos_REALM [10 + client_realm.derlen] = '\0';
	kxd->kerberos_REALM = kerberos_REALM;
	if (!ub_resolve_async (kxover_unbound_ctx,
			kerberos_REALM, DNS_TXT, DNS_INET
			kxd, cb_kxs_client_dnssec_realm, &kxd->ubqid_txt)) {
		errno = 
		goto bailout;
	}
	/* Indicate that the realm lookup is in progress */
	kxd->progress = KXS_CLIENT_DNSSEC_REALM;
	return kxd;
bailout:
	/* Cleanup processing without callback */
	_kxover_client_cleanup ();
	if (kxd != NULL) {
		free (kxd);
	}
	return NULL;
}


/* The internal _kxover_client_cleanup() operation checks all
 * fields initialised during kxover_client() and frees any
 * underlying resources.
 *
 * The progress is basically rolled off in reverse, using one
 * switch statement with cases that continue into the next.
 */
static void _kxover_client_cleanup (struct kxover_data *kxd) {
	switch (kxd->progress) {
	case KXS_CLIENT_KEY_STORING:
	case KXS_CLIENT_KX_RECEIVED:
	case KXS_CLIENT_KX_SENT:
	case KXS_CLIENT_REALMSCHECK:
		;
	case KXS_CLIENT_HANDSHAKE:
		if (kxd->tlsdata) {
			starttls_handshake_cancel (kxd->tlsdata);
			starttls_close (kxd->tlsdata);
			kxd->tlsdata = NULL;
		}
	case KXS_CLIENT_STARTTLS:
	case KXS_CLIENT_CONNECTING:
		if (kxd->kxoffer_fd >= 0) {
			close (kxd->kxoffer_fd);
			kxd->kxoffer_fd = -1;
		}
	case KXS_CLIENT_DNS_AAAA_A:
		if (kxd->ubres_aaaa != NULL) {
			ub_resolve_free (kxd->ubres_aaaa);
		} else {
			ub_cancel (kxover_unbound_ctx, kxd->unqid_aaaa);
		}
		if (kxd->ubres_a != NULL) {
			ub_resolve_free (kxd->ubres_a);
		} else {
			ub_cancel (kxover_unbound_ctx, kxd->unqid_a);
		}
	case KXS_CLIENT_DNSSEC_KDC:
		if (kxd->ubres_srv != NULL) {
			ub_resolve_free (kxd->ubres_srv);
		} else {
			ub_cancel (kxover_unbound_ctx, kxd->unqid_srv);
		}
	case KXS_CLIENT_DNSSEC_REALM:
		if (kxd->kerberos_tls_hostname != NULL) {
			free (kxd->kerberos_tls_hostname);
			kxd->kerberos_tls_hostname = NULL;
		}
		if (kxd->ubres_text != NULL) {
			ub_resolve_free (kxd->ubres_txt);
		} else {
			ub_cancel (kxover_unbound_ctx, kxd->ubqid_txt);
		}
	case KXS_CLIENT_INITIALISED:
		if (kxd->kerberos_REALM != NULL) {
			free (kxd->kerberos_REALM);
			kxd->kerberos_REALM = NULL;
	default:
		;
	}
	//TODO// Stop event watchers, cleanup
	;
}


/* Cancel the KXOVER client or server process.  We take
 * care of reasonable changes to progress, so any risk
 * due to concurrency are minimal; still, it is not so
 * good as to make this thread-safe.  Add mutex locking
 * if you need that.
 *
 * A call to either routine _kxover_client_cleanup() or
 * _kxover_server_cleanup() may have been made already;
 * this is common practice when the progress moves into
 * shared state territory; this is why only the states
 * that are either client-specific or server-specific
 * lead to a call to the respective _kxover_*_cleanup()
 * routine.
 */
static void _kxover_cleanup (struct kxover_data *kxd) {
	progress = kxd->progress;
	if        ((progress > KXS_CLIENT_PRE ) &&
	           (progress < KXS_CLIENT_POST)) {
		_kxover_client_cleanup (kxd);
	} else if ((progress > KXS_SERVER_PRE ) &&
	           (progress < KXS_SERVER_POST)) {
		_kxover_server_cleanup (kxd);
	}
}
void kxover_finish (struct kxover_data *kxd) {
	enum kxover_state orig_progress = kxd->progress;
	/* Cleanup client or server specifics, if any */
	_kxover_cleanup (kxd);
	/* If not done yet, run the callback to report errno ECANCELED */
	if ((orig_progress != KXS_CALLBACK) && (orig_progress != KXS_CLEANUP)) {
		kxd->progress = KXS_CALLBACK;
		kxd->cb (kxd->cbdata, kxd->last_errno, kxd->crealm, kxd->srealm);
		kxd->progress = KXS_CLEANUP;
	}
	/* free the memory used for KXOVER administration */
	//NOTE// crealm ownership is passed through the callback
	// if (kxd->crealm.derptr) {
	// 	free (kxd->crealm.derptr);
	// 	kxd->crealm.derptr = NULL;
	// }
	//NOTE// srealm ownership is passed through the callback
	// if (kxd->srealm.derptr) {
	// 	free (kxd->srealm.derptr);
	// 	kxd->srealm.derptr = NULL;
	// }
	free (kxd);
}
void kxover_cancel (struct kxover_data *kxd) {
	kxd->last_errno = ECANCELED;
	kxover_finish (kxd);
}
inline void kxover_client_cancel (struct kxover_data *kxd) { kxover_cancel (kxd); }
inline void kxover_server_cancel (struct kxover_data *kxd) { kxover_cancel (kxd); }


/* Having classified TCPKRB5_KXOVER_REP from downstream,
 * handle it locally by finishing realm crossover and
 * continuing processing after it completes.  This
 * involves KXOVER server validation.
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
 * to parse or setup the client, with detail in errno.
 */
struct kxover_data *kxover_client (cb_kxover_server cb, void *cbdata,
			derptr krbdata) {
	ovly_KRB_ERROR fields;
	der_unpack (&krbdata, pack_KRB_ERROR, fields, 1);
	if (der_cmp (fields.pvno), der_int_5) != 0) {
		errno = EPROTO;
printf ("DEBUG: kvno != 5\n");
		return NULL;
	}
	if (der_cmp (fields.msg_type, der_int_30) != 0) {
		errno = EPROTO;
printf ("DEBUG: msg_type != 30\n");
		return NULL;
	}
	/* Test service ticket name: 2 levels, 1st != "krbtgt" */
	bool ok = true;
	derptr der0 = fields.sname;         /* copy */
printf ("DEBUG: der0     # %d\tat %s:%d\n", der0.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_enter (der0)); /* into princname */
printf ("DEBUG: der0     # %d\tat %s:%d\n", der0.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_skip  (der0)); /* pass name-type */
printf ("DEBUG: der0     # %d\tat %s:%d\n", der0.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_enter (der0));
printf ("DEBUG: der0     # %d\tat %s:%d\n", der0.derlen, __FILE__, __LINE__);
	derptr der1 = der0;                 /* copy */
printf ("DEBUG: der0,1   # %d,%d\tat %s:%d\n", der0.derlen, der1.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_skip  (der1));
printf ("DEBUG: der0,1   # %d,%d\tat %s:%d\n", der0.derlen, der1.derlen, __FILE__, __LINE__);
	derptr der2 = der1;                 /* copy */
printf ("DEBUG: der0,1,2 # %d,%d,%d\tat %s:%d\n", der0.derlen, der1.derlen, der2.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_skip  (der2));
printf ("DEBUG: der0,1,2 # %d,%d,%d\tat %s:%d\n", der0.derlen, der1.derlen, der2.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_focus (der0));
printf ("DEBUG: der0,1,2 # %d,%d,%d\tat %s:%d\n", der0.derlen, der1.derlen, der2.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_focus (der1));
printf ("DEBUG: der0,1,2 # %d,%d,%d\tat %s:%d\n", der0.derlen, der1.derlen, der2.derlen, __FILE__, __LINE__);
	ok = ok &&  der_isnonempty (der0);
	ok = ok &&  der_isnonempty (der1);
	ok = ok && !der_isnonempty (der2);
	if (!ok) {
		errno = EBADMSG;
		return NULL;
	}
	if (der_cmp (der0, der_kstr_krbtgt) == 0) {
		errno = EPERM;
		return NULL;
	}
	// We might also check ctime, cusec, stime, susec
	// But: The origin is our trusted backend.
	return kxover_client (cb, cbdata,
				fields.crealm,  /* client realm */
				fields.realm); /* service realm */
}


/* Process a callback from Unbound, in response to a query that we
 * posed.  Perform a number of general checks depending on progress:
 *
 *  - Check that an answer is indeed supplied by Unbound
 *  - Check that progress is indeed looking for data from Unbound
 *  - Check that the answer begins with any required prefix
 *  - Check that the answer is validated by DNSSEC where needed
 *  - Check that the record type is the desired one
 *  - Check that the number of entries is only multiple if meaningful
 *
 * On failure, cleanup and move on to error state.
 *
 * On success, call a more specific callback handler and change the
 * state to the next.
 */
struct kx_ub_constraints {
	enum kxover_state progress_pre ;
	char *qprefix;
	uint16_t rrtype;
	uint8_t require_0_1_many;
	bool require_dnssec;
	bool non_fatal;
};
bool _kxover_unbound_proper (struct kxover_data *kxd,
			struct kx_ub_constraints *kuc,
			int err, struct ub_result *result) {
	/* Update cancellation and result stores */
	* (int              *) (((uint8_t *) kxd) + kuc->cancel_offset) = -1;
	* (struct ub_result *) (((uint8_t *) kxd) + kuc->result_offset) = result;
	/* Various small checks on fields */
	bool ok = true;
	ok = ok && (result != NULL);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (kuc != NULL);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (err == 0);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (result->qtype == kuc->rrtype) && (result->qclass == DNS_INET);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (strncmp (kuc->qprefix, result->qname, strlen (kuc->qprefix)) == 0);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (kxd->progress == kuc->progress_pre);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	/* Test multiplicity: 0, 1, many (where many means 1..N); -1 ignores */
	switch (kuc->require_0_1_many) {
	case 0:
		ok = ok && !result->havedata;
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
		break;
	case 1:
		ok = ok &&  result->havedata && (result->data[1] == NULL);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
		break;
	case -1:
		/* No check on the number of results */
		break;
	default: /* many, meaning 1..N */
		ok = ok &&  result->havedata;
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
		break;
	}
	/* Test for DNSSEC-secured data, if so required */
	if (kuc->require_dnssec) {
		ok = ok && !result->secure;
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	}
	/* Bogus is also useful to test when DNSSEC is not enforced */
	ok = ok && !result->bogus;
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	/* Change the progress value to the post condition */
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	if (ok) {
		kxd->progress = kuc->progress_pre;
	} else {
		if (kxd->last_errno == 0) {
			kxd->last_errno = EADDRNOTAVAIL;
		}
		kxover_finish ();
		return false;
	}
	/* Return the overall verdict */
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	return ok;
}


#define DNS_INET 1

enum dns_rrtype {
	DNS_TXT    = 16,
	DNS_SRV    = 33,
	DNS_AAAA   = 28,
	DNS_A      = 1,
};


/* Process an incoming SRV record with KDC host names for
 * the KXOVER client.  This will start an iterator that
 * passes over the following nesting:
 *  1. SRV records, in order of priority (not weight, sorry)
 *  2. AAAA/A records for the host name in the SRV record
 *  3. sockets attempting to connect to each IP address
 * A connected socket then has a secure server host name,
 * namely the name in the SRV record that we connected to.
 */
static void cb_kxs_client_dnssec_kdc (
			struct kxover_data *cbdata,
			int err, struct ub_result *result) {
	/* Perform general sanity checks and administration */
	static struct kx_ub_constraints proper = {
		.qprefix          = "_kerberos-tls._tcp.",
		.rrtype           = DNS_SRV,
		.progress_pre     = KXS_CLIENT_DNSSEC_KDC,
		.require_dnssec   = true,
		.require_0_1_many = 2,
		.result_offset    = offsetof (struct kxover_data, ubres_srv),
		.cancel_offset    = offsetof (struct kxover_data, ubqid_srv),
	};
	if (!_kxover_unbound_proper (kxd, &proper, err, result)) {
		return;
	}
	/* Iterate over SRV and AAAA/A, then connect() */
	kxover_client_connect_attempt ();
}


/* Process an incoming _kerberos TXT record for the KXOVER client.
 * This is a callback from Unbound, installed in kxover_client().
 */
static void cb_kxs_client_dnssec_realm (
			struct kxover_data *cbdata,
			int err, struct ub_result *result) {
	/* Perform general sanity checks and administration */
	static struct kx_ub_constraints proper = {
		.qprefix          = "_kerberos.",
		.rrtype           = DNS_TXT,
		.progress_pre     = KXS_CLIENT_DNSSEC_REALM,
		.require_dnssec   = true,
		.require_0_1_many = 1,
		.result_offset    = offsetof (struct kxover_data, ubres_txt),
		.cancel_offset    = offsetof (struct kxover_data, ubqid_txt),
	};
	if (!_kxover_unbound_proper (kxd, &proper, err, result)) {
		return;
	}
	/* Check the first label and ignore any appended labels */
	uint8_t label1len = *result->data[0];
	if (label1len >= result->len[0]) {
		/* Syntax error in TXT */
		kxd->last_errno = EBADMSG;
		goto bailout;
	}
	//TODO// regexpmatch: DNS style, uppercase only
	/* Construct the server realm name with "_kerberos-tls._tcp." prefixed */
	char *kerberos_tls_hostname = malloc (19 + label1len + 1);
	if (kerberos_tls_hostname == NULL) {
		/* Out of memory */
		kxd->last_errno = ENOMEM;
		goto bailout;
	}
	krb->kerberos_tls_hostname = kerberos_tls_hostname;
	memcpy (kerberos_tls_hostname   , "_kerberos-tls._tcp.");
	memcpy (kerberos_tls_hostname+19, &result->data[0][1], label1len);
	kerberos_tls_hostname [19+label1len] = '\0';
	kxd->srealm.derlen = label1len;
	kxd->srealm.derptr = kerberos_tls_hostname + 19;
	/* Continue to look for the server realm's KDC address */
	if (!ub_resolve_async (kxover_unbound_ctx,
			kerberos_tls_hostname, DNS_SRV, DNS_INET,
			kxd, cb_kxs_client_dnssec_kdc, &kxd->ubqid_srv) == 0) {
		kxd->last_errno = EADDRNOTAVAIL;
		goto bailout;
	}
	/* Success; return from this callback function */
	kxd->progress = KXS_CLIENT_DNSSEC_KDC;
	return;
bailout:
	kxover_finish ();
	return;
}


