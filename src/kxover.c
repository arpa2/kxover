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


#include "kxover.h"
#include "starttls.h"

#include <unbound.h>

#include <quick-der/api.h>
#include <quick-der/rfc4120.h>
#include <quick-der/kxover.h>


/* Forward declarations */
void kxover_finish (struct kxover_data *kxd);
static void kxover_client_connect_attempt (struct kxover_data *kxd);
static void cb_kxs_client_connecting (EV_P_ ev_io *evt, int revents);
static void cb_kxs_client_starttls (EV_P_ ev_io *evt, int revents);
static void cb_kxs_client_handshake (void *cbdata, int fd_new);
static bool kx_start_realmscheck (struct kxover_data *kxd);
static bool kx_start_dnssec_kdc (struct kxover_data *kxd, dercursor realm_name);
static void kx_start_client_kx_sending (struct kxover_data *kxd, bool _refresh_only);
static bool _parse_service_principalname (int name_type, const DER_OVLY_rfc4120_PrincipalName *princname,
			struct dercursor *out_label0, struct dercursor *out_label1);


/* The maximum number of bytes in a DERific Kerberos message */
#define MAXLEN_KERBEROS 1500


/* Definitions of DNS constants from IANA / RFCs */
#define DNS_INET 1
enum dns_rrtype {
	DNS_TXT    = 16,
	DNS_SRV    = 33,
	DNS_AAAA   = 28,
	DNS_A      = 1,
};


/* Definitions of constraints to DNS query output */
struct kx_ub_constraints {
	enum kxover_state progress_pre ;
	enum kxover_state progress_pre2;
	char *qprefix;
	uint16_t rrtype;
	int8_t require_0_1_many;
	bool require_dnssec;
	bool non_fatal;
	uint16_t result_offset;
	uint16_t cancel_offset;
};


/* Application tags used in Kerberos with KXOVER extensions */
#define APPTAG_KRB_ERROR  ( 0x40 | 0x20 | 30 )
#define APPTAG_KXOVER_REQ ( 0x40 | 0x20 | 18 )
#define APPTAG_KXOVER_REP ( 0x40 | 0x20 | 19 )


/* Quick DER path to walk into a KRB-ERROR (whose der_header has
 * already been analysed and skipped) and find the error-code.
 */
static const derwalk krberror2code [] = {
	DER_WALK_ENTER | DER_TAG_SEQUENCE,         // SEQUENCE { ... }
	DER_WALK_SKIP  | DER_TAG_INTEGER,          // kvno 5
	DER_WALK_SKIP  | DER_TAG_INTEGER,          // msg-type 30
	DER_WALK_OPTIONAL,
	DER_WALK_SKIP  | DER_TAG_GENERALIZEDTIME,  // ctime
	DER_WALK_OPTIONAL,
	DER_WALK_SKIP  | DER_TAG_INTEGER,          // cusec
	DER_WALK_SKIP  | DER_TAG_GENERALIZEDTIME,  // stime
	DER_WALK_SKIP  | DER_TAG_INTEGER,          // susec
	DER_WALK_ENTER | DER_TAG_INTEGER,          // error-code
	DER_WALK_END
};


/* Quick DER packer for KX-REQ-MSG and/or KX-REP-MSG,
 * but only to decode shallow versions, returning the contained
 * KX-OFFER for separate analysis.
 */
static const derwalk pack_msg_shallow [] = {
	DER_PACK_ENTER | DER_TAG_SEQUENCE,
	DER_PACK_STORE | DER_TAG_INTEGER,	/* pvno(5) */
	DER_PACK_STORE | DER_TAG_INTEGER,	/* msg-type(...) */
	DER_PACK_ANY,
	DER_PACK_LEAVE,
	DER_PACK_END
};


/* Quick DER packer and typedef for a KX-OFFER message.
 */
static const derwalk pack_KX_OFFER [] = {
	DER_PACK_kxover_KX_OFFER,
	DER_PACK_END
};
static const derwalk pack_KX_REQ_MSG [] = {
	DER_PACK_kxover_KX_REQ_MSG,
	DER_PACK_END
};
static const derwalk pack_KX_REP_MSG [] = {
	DER_PACK_kxover_KX_REP_MSG,
	DER_PACK_END
};

typedef DER_OVLY_kxover_KX_OFFER   ovly_KX_OFFER  ;
typedef DER_OVLY_kxover_KX_REQ_MSG ovly_KX_REQ_MSG;
typedef DER_OVLY_kxover_KX_REP_MSG ovly_KX_REP_MSG;

typedef DER_OVLY_rfc4120_PrincipalName pack_PrincipalName;


/* Quick DER pack/unpack instructions for KRB-ERROR.
 */
static const derwalk pack_KRB_ERROR [] = { DER_PACK_rfc4120_KRB_ERROR, DER_PACK_END };
typedef DER_OVLY_rfc4120_KRB_ERROR ovly_KRB_ERROR;


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
			struct dercursor client_realm,
			struct dercursor service_realm);


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
	struct dercursor crealm;
	struct dercursor srealm;
	struct dercursor kx_recv;
	struct dercursor kx_send;
	ovly_KX_REQ_MSG kx_req;
	ovly_KX_REP_MSG kx_rep;
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
	ev_timer ev_timeout;
	ev_io ev_kxcnx;
	uint8_t salt [32];
	struct dercursor kxname2 [2];
	struct iterator iter_srv;
	struct iterator iter_aaaa_a;
} kxover_t;


/* Reset an iterator.  This may be done initially or when
 * the need arises to start again.  The routine is generic.
 */
static void iter_reset (struct iterator *it) {
	// it->cursor  = 0;
	// it->current = 0;
	// it->prepare = 0;
	// it->started = false;
	// it->stopped = false;
	memset (it, 0, sizeof (it));
}


/* The event loop for KXOVER operations.
 */
static struct ev_loop *kxover_loop;


/* The Unbound library context for KXOVER lookups.
 */
static struct ub_ctx *kxover_unbound_ctx = NULL;


/* The Unbound library watcher, to trigger _cb_kxover_unbound().
 */
static ev_io kxover_unbound_watcher;


/* DER-encoded data:
 *  - der_notfound should be in the KRB-ERROR error-code for NOTFOUND.
 *  - der_int_5, _18, _19 and _30 encode integers 5, 18, 19 and 30.
 *  - der_kstr_krbtgt encodes the "krbtgt" as KerberosString.
 */
static const uint8_t const der_notfound    [] = { 0x07 };
static const uint8_t const der_int_5       [] = { 0x02, 0x01, 5 };
static const uint8_t const der_int_18      [] = { 0x02, 0x01, 18 };
static const uint8_t const der_int_19      [] = { 0x02, 0x01, 19 };
static const uint8_t const der_int_30      [] = { 0x02, 0x01, 30 };
static const uint8_t const der_kstr_krbtgt [] = { 'k', 'r', 'b', 't', 'g', 't' };
static const struct dercursor dercrs_notfound     = { .derptr = (uint8_t *) der_notfound,    .derlen = sizeof(der_notfound   ) };
static const struct dercursor dercrs_int_5        = { .derptr = (uint8_t *) der_int_5,       .derlen = sizeof(der_int_5      ) };
static const struct dercursor dercrs_int_18       = { .derptr = (uint8_t *) der_int_18,      .derlen = sizeof(der_int_18     ) };
static const struct dercursor dercrs_int_19       = { .derptr = (uint8_t *) der_int_19,      .derlen = sizeof(der_int_19     ) };
static const struct dercursor dercrs_int_30       = { .derptr = (uint8_t *) der_int_30,      .derlen = sizeof(der_int_30     ) };
static const struct dercursor dercrs_kstr_krbtgt  = { .derptr = (uint8_t *) der_kstr_krbtgt, .derlen = sizeof(der_kstr_krbtgt) };


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
static bool iter_srv_next (struct iterator *it, struct ub_result *result) {
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


/* Iterate over AAAA and A records.  We shall use positive cursors 0,1,...
 * for AAAA and negative -1,-2,... for A records.  This allows us to
 * have one iterator working on two sets of answers.  Iteration starts
 * with IPv6, of course.
 */
static bool iter_aaaa_a_next (struct iterator *it, struct ub_result *aaaa, struct ub_result *a) {
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
static bool _kxover_unbound_proper (struct kxover_data *kxd,
			struct kx_ub_constraints *kuc,
			int err, struct ub_result *result) {
	/* Update cancellation and result stores */
	* (int               *) (((uint8_t *) kxd) + kuc->cancel_offset) = -1;
	* (struct ub_result **) (((uint8_t *) kxd) + kuc->result_offset) = result;
	/* Various small checks on fields */
	bool ok = true;
	ok = ok && (result != NULL);
extern int printf (const char *__restrict __format, ...);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (kuc != NULL);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (err == 0);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (result->qtype == kuc->rrtype) && (result->qclass == DNS_INET);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && (strncmp (kuc->qprefix, result->qname, strlen (kuc->qprefix)) == 0);
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	ok = ok && ((kxd->progress == kuc->progress_pre) || (kxd->progress == kuc->progress_pre2));
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
		kxover_finish (kxd);
		return false;
	}
	/* Return the overall verdict */
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	return ok;
}


/* Process incoming AAAA and A records with addresses to
 * connect to from the KXOVER client.  Both types of address
 * must have arrived before the iteration over addresses
 * commences.
 */
static void cb_kxs_client_dns_aaaa_a (
			void *cbdata,
			int err, struct ub_result *result) {
	struct kxover_data *kxd = cbdata;
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
		kxd->last_errno = EBADMSG;
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
		kxd->last_errno = EBADMSG;
		goto bailout;
	}
	/* Reset the iterator for AAAA and A; initiate connection attempts */
	iter_reset (&kxd->iter_aaaa_a);
	kxover_client_connect_attempt (kxd);
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
			kxd->kerberos_tls_hostname, DNS_AAAA, DNS_INET,
			kxd, cb_kxs_client_dns_aaaa_a, &kxd->ubqid_srv);
	bool ok4 = ub_resolve_async (kxover_unbound_ctx,
			kxd->kerberos_tls_hostname, DNS_A   , DNS_INET,
			kxd, cb_kxs_client_dns_aaaa_a, &kxd->ubqid_srv);
	/* If only one got started, cancel the whole batch */
	if (ok4 != ok6) {
		ub_cancel (kxover_unbound_ctx,
				ok4 ? kxd->ubqid_a : kxd->ubqid_aaaa);
		kxd->last_errno = ENXIO;
		goto bailout;
	}
	/* Update the state and await progress */
	kxd->progress = KXS_CLIENT_DNS_AAAA_A;
	return;
bailout:
	kxover_finish (kxd);
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
static void kxover_client_connect_attempt (struct kxover_data *kxd) {
	int sox = -1;
	/* Prepare SRV iteration; not stopped but started */
	if (!kxd->iter_srv.started) {
		iter_srv_next (&kxd->iter_srv, kxd->ubres_srv);
	}
	if (kxd->iter_srv.stopped) {
		kxd->last_errno = EHOSTUNREACH;
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
			kxd->last_errno = EHOSTUNREACH;
			goto bailout;
		}
	}
	/* Create a socket to connect over TCP */
	int adrfam = (kxd->iter_aaaa_a.cursor >= 0) ? AF_INET6 : AF_INET;
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
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sa;
		salen = sizeof (*sin6);
		memcpy (&sin6->sin6_addr,
			kxd->ubres_aaaa->data [kxd->iter_aaaa_a.cursor],
			16);
		sin6->sin6_port = port_net_order;
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *) &sa;
		salen = sizeof (*sin);
		memcpy (&sin->sin_addr,
			kxd->ubres_aaaa->data [-1-kxd->iter_aaaa_a.cursor],
			4);
		sin->sin_port = port_net_order;
	}
	/* Setup event handling with a connect() responder as callback */
	ev_io_init (&kxd->ev_kxcnx, cb_kxs_client_connecting, sox, EV_WRITE | EV_ERROR);
	ev_io_start (kxover_loop, &kxd->ev_kxcnx);
	/* Finally connect to the remote's AAAA/A and the port from SRV */
	if (connect (sox, &sa, salen) < 0) {
		/* Some values in errno are caused by the deferral */
		if ((errno != EINPROGRESS) && (errno != EWOULDBLOCK) && (errno != EAGAIN)) {
			kxd->last_errno = errno;
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
	kxover_finish (kxd);
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
				offsetof (struct kxover_data, ev_kxcnx));
	ev_io_stop (EV_A_ evt);
	/* On failure, try again on any further addresses */
	if (revents & EV_ERROR) {
		kxover_client_connect_attempt (kxd);
		return;
	}
	/* Once we are connected, we switch the socket to reading mode */
	ev_io_init (evt, cb_kxs_client_starttls,
			kxd->kxoffer_fd, EV_READ | EV_ERROR);
	ev_io_start (kxover_loop, evt);
	/* Send the STARTTLS flag */
	uint8_t buf4 [4];
	* (uint32_t *) buf4 = htonl (0x80000001);
	if (send (kxd->kxoffer_fd, buf4, 4, 0) != 4) {
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
				offsetof (struct kxover_data, ev_kxcnx));
	/* For now, stop reports from the socket */
	ev_io_stop (EV_A_ evt);
	/* Bail out when socket errors occurred */
	if (revents & EV_ERROR) {
		kxd->last_errno = EIO;
		goto bailout;
	}
	/* Read the STARTTLS reply and check it is what we need */
	uint8_t ist4 [4];
	static uint8_t soll4 [4] = { 0x80, 0x00, 0x00, 0x01 };
	if (read (kxd->kxoffer_fd, ist4, 4) != 4) {
		kxd->last_errno = EINTR;
		goto bailout;
	}
	if (memcmp (ist4, soll4, 4) != 0) {
		kxd->last_errno = EPROTO;
		goto bailout;
	}
	/* Ask the Kerberos interface for the KDC name for kxd->crealm */
	struct dercursor server_kdc;
	struct dercursor client_kdc;
	server_kdc.derptr = kxd->ubres_srv->data [kxd->iter_srv.cursor] + 6;
	server_kdc.derlen = kxd->ubres_srv->len  [kxd->iter_srv.cursor] - 6;
	client_kdc = kerberos_kdc_hostname (kxd->crealm);
	if (!der_isnonempty (&client_kdc)) {
		kxd->last_errno = ENOENT;
		goto bailout;
	}
	/* Both sides are now ready for TLS, so proceed */
	if (!starttls_handshake (kxd->kxoffer_fd,
			client_kdc,
			server_kdc,
			&kxd->tlsdata,
			cb_kxs_client_handshake, kxd)) {
		kxd->last_errno = errno;
		goto bailout;
	}
	kxd->progress = KXS_CLIENT_HANDSHAKE;
	return;
bailout:
	kxover_finish (kxd);
}


/* The starttls.c module has reached a verdict on the TLS handshake.
 * This is reflected in fd_new, which is <0 on error or >=0 on success.
 * When failed, we do not try elsewhere, but fail the client attempt.
 */
static void cb_kxs_client_handshake (void *cbdata, int fd_new) {
	struct kxover_data *kxd = cbdata;
	/* Test if the TLS handshake succeeded */
	if (fd_new < 0) {
		goto bailout;
	}
	/* Check the realm names against the TLS certificates */
	if (!kx_start_realmscheck (kxd)) {
		/* kxd->last_errno has been set */
		goto bailout;
	}
	/* Continue into realm checking */
	kxd->progress = KXS_CLIENT_REALMSCHECK;
	return;
bailout:
	return;
};


/* After the TLS handshake has succeeded and the client and service
 * realm names are known, the _REALMSCHECK can be started.  This is
 * possible on the client or server, as desired; the corresponding
 * kxd->progress must be set before or right after calling this
 * helper function.
 *
 * Return true on success, or false with errno set on failure.
 */
static bool kx_start_realmscheck (struct kxover_data *kxd) {
	/* Initiate checks for both realm names by starttls.c */
	bool r_ok = starttls_remote_realm_check_certificate (
			kxd->srealm,
			kxd->tlsdata,
			cb_kxs_either_realmscheck, kxd);
	bool l_ok = starttls_local_realm_check_certificate (
			kxd->crealm,
			kxd->tlsdata,
			cb_kxs_either_realmscheck, kxd);
	/* Both sides must be checked, otherwise cancel */
	if (r_ok != l_ok) {
		starttls_cancel (kxd->tlsdata);
		kxd->last_errno = EIDRM;
		goto bailout;
	}
	return true;
bailout:
	kxover_finish (kxd);
	return false;
}


/* The starttls.c module calls back whether each realm is mentioned
 * in the certificate at the same side of the TLS connection.
 * This function can be used in client or server mode, as long as
 * kxd->progress is set to _REALMSCHECK (and, on the second call, it
 * will automatically update to _REALM2CHECK).
 */
static void cb_kxs_either_realmscheck (void *cbdata, bool success) {
	struct kxover_data *kxd = cbdata;
	/* Ensure success */
	if (!success) {
		kxd->last_errno = EACCES;
		/* During the 2nd, we will goto bailout */
	}
	/* Hold off activity during the first callback (of two) */
	if (kxd->progress == KXS_CLIENT_REALMSCHECK) {
		/* Change progress to "seen one, one more to come" */
		kxd->progress = KXS_CLIENT_REALM2CHECK;
		return;
	} else if (kxd->progress == KXS_SERVER_REALMSCHECK) {
		/* Change progress to "seen one, one more to come" */
		kxd->progress = KXS_SERVER_REALM2CHECK;
		return;
	}
	/* Given two checked realms, we look for last_errno */
	if (kxd->last_errno == EACCES) {
		goto bailout;
	}
	/* Given two correct realms, proceed to the subsequent phase */
	if (kxd->progress == KXS_SERVER_REALM2CHECK) {
		/* Continue into DNS, asking for the client KDC's SRV records */
		if (!kx_start_dnssec_kdc (kxd, kxd->crealm)) {
			/* kdc->last_errno was set by kx_start_dnssec_kdc() */
			goto bailout;
		}
		kxd->progress = KXS_SERVER_DNSSEC_KDC;
	} else if (kxd->progress == KXS_CLIENT_REALM2CHECK) {
		/* Continue into sending KX-OFFER */
		kx_start_client_kx_sending (kxd);
		kxd->progress = KXS_CLIENT_KX_SENDING;
	} else {
		/* Fail with the message that mentions both acceptable states */
		assert ((kxd->progress == KXS_CLIENT_REALM2CHECK) || (kxd->progress == KXS_SERVER_REALM2CHECK));
		kxd->last_errno = ENOSYS;
		goto bailout;
	}
	return;
bailout:
	kxover_finish (kxd);
}


/* Construct a KX-OFFER from the client to the server, and wait
 * for the corresponding KX-OFFER being returned.
 *
 * We consider the following information vital in the KX-OFFER:
 *  - ticket request Realm: SERVICE.REALM
 *  - ticket PrincipalName: krbtgt/CLIENT.REALM
 *  - salt, 32 bytes of locally generated random material
 *  - kvno is left open to the service KDC
 *  - enctypes that are acceptable to the client
 *  - from/till, requested begin and end of validity
 *
 * When we already have a ticket and are merely refreshing it
 * before it expires, we could set a future from timestamp, so
 * we have time to process the new key and initiate it at the
 * same time as the service KDC.  When this is a new crossover
 * request, we are in a hurry but also have no risk of clashes,
 * so we can activate immediately.
 * TODO: For now, _refresh_only will not be used for delay.
 */
#ifdef TODO_0
static void kx_start_client_kx_sending (struct kxover_data *kxd, bool _refresh_only) {
	/* Create basic setup for the kx_req */
	ovly_KX_REQ_MSG *msg = &kxd->kx_req;
	msg->pvno = dercrs_int_5;
	msg->msg_type = dercrs_int_18;
	/* Fill in the ticket PrincipalName and Realm */
	kxd->kxname2[0] = dercrs_kstr_krbtgt;
	kxd->kxname2[1] = kxd->crealm;
	msg->offer.kxrealm = kxd->srealm;
	/* Set the enctypes to the ones allowed locally */
	//TODO// enctypes-der-from-kerberos
	//TODO// set from to "now"
	//TODO// set till to "now" + configured #days
	/* Fill the salt with random bytes */
	if (!kerberos_prng (kxd->salt, sizeof (kxd->salt))) {
		kxd->last_errno = errno;
		goto bailout;
	}
	msg->salt.derptr = &kxd->salt[0];
	msg->salt.derlen = sizeof (kxd->salt);
	/* Map the fields in kx_req to a DER message kx_send */
	der_prepack (&kxd->kxname2[0], 2, &msg->kxname, &kxd->kx_req.TODO);
	size_t   reqlen = der_pack (pack_KX_REQ_MSG, msg, NULL);
	uint8_t *reqptr = malloc (kxd->kx_send.derlen);
	if (reqptr == NULL) {
		errno = ENOMEM;
		goto bailout;
	der_pack (pack_KX_REQ_MSG, msg, reqptr + reqlen);
	kxd->kx_send.derlen = reqlen;
	kxd->kx_send.derptr = reqptr;
	/* Now send the kx_send message over kxoffer_fd */
	if (send (kxd->kxoffer_fd, reqptr, reqlen, 0) != reqlen) {
		/* Close the socket and let event handler signal it */
		/* Note: We could send with callbacks, if need be */
		close (kxd->kxoffer_fd);
		kxd->kxoffer_fd = -1;
		return;
	}
	/* Register the next callback function to collect the response */
	ev_io_init (evt, cb_kxs_client_kx_receiving, fd, EV_READ | EV_ERROR);
	ev_io_start (kxover_loop, evt);
	return;
bailout:
	kxover_finish (kxd);
}
#endif


/* Callback for incoming traffic from the server, to be stored
 * as KX-OFFER in kxd->kx_recv, possibly arriving in parts.  The
 * first part must be at least 5 bytes to be considered, however.
 */
static void cb_kxs_client_kx_receiving (EV_P_ ev_io *evt, int revents) {
	struct kxover_data *kxd =
		(struct kxover_data *) (
			((uint8_t *) evt) -
				offsetof (struct kxover_data, ev_kxcnx));
	/* Bail out immediately when there are connection problems */
	if (revents & EV_ERROR) {
		kxd->last_errno = EIO;
		goto bailout;
	}
	/* Initially collect and analyse the initial 5 bytes */
	if (kxd->kx_recv.derptr == NULL) {
		uint8_t buf4 [4];
		uint8_t tag;
		size_t  len;
		uint8_t hlen;
		//TODO//NOT// dercursor sofar;
		if (recv (kxd->kxoffer_fd, buf4, 4, 0) != 4) {
			/* Reject silly small transmission */
			kxd->last_errno = EBADMSG;
			goto bailout;
		}
		uint32_t tmplen = ntohl (* (uint32_t *) buf4);
		kxd->kx_recv.derptr = calloc (kxd->kx_recv.derlen, 1);
		if (kxd->kx_recv.derptr == NULL) {
			kxd->last_errno = ENOMEM;
			goto bailout;
		}
		kxd->kx_recv.derlen = tmplen;
		kxd->kxoffer_recvlen = 0;
	}
	/* Try to receive data (and silently skip on failure) */
	ssize_t recvlen = recv (kxd->kxoffer_fd,
				kxd->kx_recv.derptr + kxd->kxoffer_recvlen,
				kxd->kx_recv.derlen - kxd->kxoffer_recvlen,
				0);
	if (recvlen < 0) {
		/* Error, possibly temporary; continue to wait for EV_READ | EV_ERROR */
		return;
	}
	kxd->kxoffer_recvlen += recvlen;
	if (kxd->kxoffer_recvlen < kxd->kx_recv.derlen) {
		/* The buffer isn't complete; continue to wait for EV_READ | EV_ERROR */
		return;
	}
	/* When all arrived, stop further socket receiving */
	ev_io_stop (EV_A_ evt);
	/* Compare the outer DER length and unpack the KX-REP-MSG */
	struct dercursor inicrs = kxd->kx_recv;
	uint8_t tag;
	size_t len;
	uint8_t hlen;
	if ((der_header (&inicrs, &tag, &len, &hlen) != 0) || (len+hlen != kxd->kx_recv.derlen)) {
		/* Error analysing the header */
		kxd->last_errno = EBADMSG;
		goto bailout;
	}
	if (!kxoffer_unpack (kxd->kx_recv, der_int_19, kxd->kx_rep)) {
		kxd->last_errno = errno;
		goto bailout;
	}
	/* Analyse the data and compare kx_req and kx_rep */
	if (der_cmp (kxd->kx_req.nonce, kxd->kx_rep.nonce) != 0) {
		/* Nonce in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	if (der_cmp (kxd->kx_req.from, kxd->kx_rep.from) != 0) {
		/* Request Time in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	if (der_cmp (kxd->kx_req.kxrealm, kxd->kx_rep.kxrealm) != 0) {
		/* Realm in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	struct dercursor service_realm;
	if (!_parse_service_principalname (2, kxd->kxname, NULL, &service_realm)) {
		kxd->last_errno = errno;
		goto bailout;
	}
	//TODO// regexp: all-lowercase requirement
	if (der_cmp (service_realm, kxd->kxname2[1]) != 0) {
		/* Service hostname in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	//TODO// For now, in lieu of spec certainty, enforce kvno presence in KX-REP
	if (!der_isnonempty (kxd->kx_rep.kvno)) {
		goto bailout_EPROTO;
	}
	/* End this callback, and continue with key derivation */
	if (!kx_start_key_deriving (kxd)) {
		/* kxd->last_errno is set by kx_start_key_deriving() */
		/* ev_io_stop() was already called */
		goto bailout_stopped;
	}
	kxd->progress = KXS_CLIENT_KEY_DERIVING;
	return;
bailout_EPROTO:
	errno = EPROTO;
	/* ...and continue: */
bailout:
	ev_io_stop (EV_A_ evt);
	/* ...and continue: */
bailout_stopped:
	kxover_finish (kxd);
}


/* Process an Unbound callback, presumably in response to
 * a query that we posted from here.  We delegate control
 * to Unbound's processor, which will deliver via query
 * callbacks.
 */
static void _cb_kxover_unbound (EV_P_ ev_io *_evt, int _revents) {
	ub_process (kxover_unbound_ctx);
}


/* Start key determination and storage in the KDC database.
 * On a KXOVER server, this runs before responding so the KDC
 * is sure to have the key; on a KXOVER client, this runs
 * after receiving a response because that information is
 * needed to perform these computations.  After this call,
 * progress should be set to KXS_x_KEY_DERIVING.
 */
static bool kx_start_key_deriving (kxover_data *kxd) {
	/* Determine label and salt to use */
	static const struct dercursor label = {
		.derptr = "EXPERIMENTAL-EXPORTER-INTERNETWIDE-KXOVER",
		.derlen = 41,
		// .derptr = "EXPORTER-INTERNETWIDE-KXOVER",
		// .derlen = 28,
	};
	assert (strlen (label.derptr) == label.derlen);
	static const struct dercursor no_ctxval = {
		.derptr = NULL,
		.derlen = 0,
	};
	/* Determine the key size needed, in bytes */
	uint16_t keylen = 32;
	uint8_t key [keylen];
	/* Ask the starttls.c module to derive a shared key */
	if (!starttls_export_key (label, no_ctxval,
			keylen, key,
			cb_kxs_either_key_deriving, kxd)) {
		kxd->last_errno = errno;
		goto bailout;
	}
	return;
bailout:
	kxover_finish (kxd);
}


/* Unpack an incoming KX-OFFER message, contained in either
 * KX-REQ-MSG (msg_type 18) or KX-REP-MSG (msg_type 19).
 * Store the resulting dercrs values in outvars.
 *
 * Return true on success, or false with errno set on failure.
 */
static bool kxoffer_unpack (dercursor msg, dercursor msg_type,
			ovly_KX_OFFER *outvars) {
	/* First unpack the message surroundings of KX-*-MSG */
	dercursor msg_ovly [3];  /* 5, msg-type, KX-OFFER */
	if (der_unpack (&msg, pack_msg_shallow, msg_ovly, 1) != 0) {
		errno = EBADMSG;
		goto bailout;
	}
	/* Verify the pvno and msg-type fields */
	if (der_cmp (msg_ovly [0], der_int_5) != 0) {
		errno = EPROTO;
		goto bailout;
	}
	if (der_cmp (msg_ovly [1], msg_type) != 0) {
		errno = EPROTO;
		goto bailout;
	}
	/* Zoom in on the contained KX-OFFER */
	msg = msg_ovly [2];
	/* Unpack the KX-OFFER into outvars */
	if (der_unpack (&msg, pack_KX_OFFER, outvars, 1) != 0) {
	errno = EBADMSG;
		goto bailout;
	}
	/* We succeeded in finding the KX-OFFER in the DER message */
	return true;
bailout:
	return false;
}


/* Parse the DER format for a PrincipalName, and check
 * it to either be krbtgt/REALM@REALM (for name_type 2)
 * or another service in service/host@REALM (for
 * name_type 3).  The output is true when the name has
 * a proper structure, and the level0 and level1 strings
 * are output.
 *
 * Note that unpack() only gets halfway with PrincipalName;
 * the name-string in the PrincipalName is a SEQUENCE OF
 * KerberosString, and must be iterated manually.  This is
 * what this function does.
 *
 * Return true on success, or false with errno set on failure.
 */
static bool _parse_service_principalname (int name_type, const pack_PrincipalName *princname,
			struct dercursor *out_label0, struct dercursor *out_label1) {
	bool ok = true;
	/* We simply ignore the name_type, as directed by RFC 4120 */
	derptr der0 = princname.name_string;         /* copy */
int printf (const char *__restrict __format, ...);
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
		goto bad_message;
	}
	bool is_krbtgt = (der_cmp (der0, der_kstr_krbtgt) == 0);
	if (name_type == 2) {
		if (!is_krbtgt) {
			goto not_permitted;
		}
	} else if (name_type == 3) {
		if (is_krbtgt) {
			goto not_permitted;
		}
	} else {
		goto not_permitted;
	}
	/* Success!  Deliver outputs and return cheerfully. */
	if (out_label1 != NULL) {
		*out_label1 = der0;
	}
	if (out_label2 != NUL) {
		*out_label2 = der1;
	}
	return true;
bad_message:
	errno = EBADMSG;
	return false;
not_permitted:
	errno = EPERM;
	return false;
}


/* Start the _DNSSEC_KDC procedure on client or server.
 * This needs a realm name, provided as a parameter.
 * After success, the progress variable must be set to the
 * apropriate _DNSSEC_KDC value for the client or server.
 */
static bool kx_start_dnssec_kdc (struct kxover_data *kxd, dercursor realm_name) {
	/* Construct the server realm name with "_kerberos-tls._tcp." prefixed */
	char *kerberos_tls_hostname = malloc (19 + realmname->derlen + 1);
	if (kerberos_tls_hostname == NULL) {
		/* Out of memory */
		kxd->last_errno = ENOMEM;
		goto bailout;
	}
	krb->kerberos_tls_hostname = kerberos_tls_hostname;
	memcpy (kerberos_tls_hostname   , "_kerberos-tls._tcp.");
	memcpy (kerberos_tls_hostname+19, realmname->derptr, realmname->derlen);
	kerberos_tls_hostname [19+realmname->derlen] = '\0';
	/* Continue to look for the server realm's KDC address */
	if (!ub_resolve_async (kxover_unbound_ctx,
			kerberos_tls_hostname, DNS_SRV, DNS_INET,
			kxd, cb_kxs_either_dnssec_kdc, &kxd->ubqid_srv) == 0) {
	}
	/* Success */
	return true;
bailout:
	return false;
}


/* Process an incoming SRV record with KDC host names for
 * the KXOVER client or server.  This will start an iterator
 * over the SRV records, but what is done inside the loop
 * differs: a client will lookup AAAA/A records and try to
 * connect; a server will test if the hostname matches the
 * certificate-negotiated server name.
 */
static void cb_kxs_either_dnssec_kdc (
			struct kxover_data *cbdata,
			int err, struct ub_result *result) {
	/* Perform general sanity checks and administration */
	static struct kx_ub_constraints proper = {
		.qprefix          = "_kerberos-tls._tcp.",
		.rrtype           = DNS_SRV,
		.progress_pre     = KXS_SERVER_DNSSEC_KDC,
		.progress_pre2    = KXS_CLIENT_DNSSEC_KDC,
		.require_dnssec   = true,
		.require_0_1_many = 2,
		.result_offset    = offsetof (struct kxover_data, ubres_srv),
		.cancel_offset    = offsetof (struct kxover_data, ubqid_srv),
	};
	if (!_kxover_unbound_proper (kxd, &proper, err, result)) {
		return;
	}
	/* Iterate over SRV, distinguishing client and server */
	if (kxd->progress == KXS_SERVER_DNSSEC_KDC) {
		/* Signal the new state, even if we currently don't wait in it */
		kxd->progress = KXS_SERVER_HOSTCHECK;
		/* On a server, check the host name against the certificate */
		iter_srv_reset (&kxd->iter_srv);
		while (iter_srv_next (&kxd->iter_srv, kxd->ubres_srv)) {
			if (starttls_remote_hostname_check_certificate (
					struct derptr hostname,
					struct starttls_data *tlsdata)) {
				/* Found it.  Move on to _KEY_DERIVING. */
				if (!kx_start_key_deriving (kxd)) {
					kxd->last_errno = ENOSYS;
					goto bailout;
				}
				kxd->progress = KXS_SERVER_KEY_DERIVING;
				return;
			} else {
				/* Mismatch.  Try the next. */
				continue;
			}
		}
		kxd->last_errno = ENOENT;
		goto bailout;
	} else if (kxd->progress == KXS_CLIENT_DNSSEC_KDC) {
		/* On a client, work towards a connected socket */
		kxover_client_connect_attempt ();
		return;
	} else {
		/* Trigger an error with an assertion that cannot succeed */
		assert ((kxd->progress == KXS_SERVER_DNSSEC_KDC) || (kxd->progress == KXS_CLIENT_DNSSEC_KDC));
		return;
}
bailout:
	kxover_finish (kxd);
	return;
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
	/* Look for the KDC based on the _kerberos TXT realm */
	//TODO//BUG// Longevity of realm information copy!!!
	kxd->srealm.derptr = &result->data[0][1];
	kxd->srealm.derlen = label1len;
	if (!kx_start_dnssec_kdc (kxd, kxd->srealm)) {
		/* kdc->last_errno was set by kx_start_dnssec_kdc() */
		goto bailout;
	}
	/* Success; return from this callback function */
	kxd->progress = KXS_CLIENT_DNSSEC_KDC;
	return;
bailout:
	kxover_finish (kxd);
	return;
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
	ev_io_init (&kxover_unbound_watcher, _cb_kxover_unbound, fd, EV_READ | EV_ERROR);
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
 *
 * The server borrows the ownership of kx_req_msg
 * for the duration of its processing, that data is
 * assumed to be stable until the callback.
 */
struct kxover_data *kxover_server (cb_kxover_server cb, void *cbdata,
			derptr kx_req_msg, int kxoffer_fd) {
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
	kxd->cbdata = cbdata;
	ev_timer_init (&kxd->ev_timeout, cb_kxover_timeout, 60.0, 0.0);
	kxd->cb = cb;
	kxd->progress = KXS_SERVER_INITIALISED;
	/* Take in the server message, and unpack its DER */
	kxd->kx_recv = kx_req_msg;
	if (!kxoffer_unpack (kxd, kx_req_msg, der_int_18)) {
		/* errno is set to EBADMSG in kxoffer_unpack() */
		kxd->last_errno = errno;
		goto bailout;
	}
	kxd->progress = KXS_SERVER_KX_RECEIVING;
	/* Continue by checking the realms against the TLS certificate */
	if (!kx_start_realmscheck (kxd)) {
		/* kxd->last_errno has been set by kx_start_realmscheck() */
		goto bailout;
	}
	kxd->progress = KXS_SERVER_REALMSCHECK;
	return kxd;
bailout:
	free (kxd);
	return NULL;
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
	ev_timer_init (&kxd->ev_timeout, kxover_timeout_fire, 60.0, 0.0);
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
		errno = ENXIO;
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
	case KXS_CLIENT_KEY_DERIVING:
	case KXS_CLIENT_KX_RECEIVING:
		if (kxd->rep_msg.derptr) {
			free (kxd->rep_msg.derptr);
			kxd->rep_msg.derptr = NULL;
		}
		kxd->rep_msg.derlen = 0;
	case KXS_CLIENT_KX_SENDING:
		if (kxd->req_msg.derptr) {
			free (kxd->req_msg.derptr);
			kxd->req_msg.derptr = NULL;
		}
		kxd->req_msg.derlen = 0;
	case KXS_CLIENT_REALM2CHECK:
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
	/* First of all, disarm the timeout timer */
	ev_timer_stop (kxover_loop, &kxd->ev_timeout);
	/* Now record the current progress, used later */
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
inline static void kxover_client_cancel (struct kxover_data *kxd) { kxover_cancel (kxd); }
inline static void kxover_server_cancel (struct kxover_data *kxd) { kxover_cancel (kxd); }



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
 * to parse or setup the client, with detail in errno.
 * This function will regularly fail, but it can be
 * freely tried.  Other errors or otherwise unfit
 * messages will simply return failure.
 */
struct kxover_data *kxover_client_for_KRB_ERROR (
			cb_kxover_server cb, void *cbdata,
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
	struct dercursor der0, der1;
	if (!_parse_service_principalname (3, &fields.sname, NULL, NULL)) {
		/* errno has been set in the test */
printf ("DEBUG: PrincipalName not acceptable\n");
		return NULL;
	}
	// We might also check ctime, cusec, stime, susec
	// But: The origin is our trusted backend.
printf ("DEBUG: Starting KXOVER client for KRB-ERROR\n");
	return kxover_client (cb, cbdata,
				fields.crealm,   /* client realm */
				fields. realm); /* service realm */
}


/* Add a timeout to the given KXOVER handle.  This can be called after
 * a successful kxover_client() or kxover_server() call.  It will lead
 * to an automatic breakdown of communications and a callback with
 * error code ETIMEDOUT when the given time (in seconds) expires before
 * the exchange is done.  Call this again to restart the timer.  Any
 * timeout value <= 0.0 will stop the timer.
 */
void kxover_timeout (struct kxover_data *kxd, float timeout_seconds) {
	ev_timer_stop (kxover_loop, &kxd->ev_timeout);
	if (timeout_seconds > 0.0) {
		ev_timer_set (&kxd->ev_timeout, timeout_seconds, 0.0);
		ev_timer_start (kxover_loop, &kxd->ev_timeout);
	}
}


/* Fire the timeout and make it report ETIMEDOUT.
 */
static void cb_kxover_timeout (EV_P_ ev_timer evt, int _revents) {
	struct kxover_data *kxd =
		(struct kxover_data *) (
			((uint8_t *) evt) -
				offsetof (struct kxover_data, ev_timeout));
	kxd->last_errno = ETIMEDOUT;
	kxover_finish (kxd);
}


