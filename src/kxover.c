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


#ifdef DEBUG
#include <stdio.h>
#include <fcntl.h>
#endif

#include "kxover.h"
#include "starttls.h"
#include "kerberos.h"
#include "socket.h"

#include <time.h>

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
static void cb_kxs_either_realmscheck (void *cbdata, bool success);
static bool kxoffer_unpack (dercursor msg, dercursor msg_type,
			DER_OVLY_kxover_KX_OFFER *outvars);
static bool kx_start_key_deriving (struct kxover_data *kxd);
static void cb_kxover_timeout (EV_P_ ev_timer *evt, int _revents);
static void _kxover_client_cleanup (struct kxover_data *kxd);
static void cb_kxs_either_dnssec_kdc (void *cbdata, int err, struct ub_result *result);
static void cb_kxs_client_kx_receiving (EV_P_ ev_io *evt, int revents);


/* The states that a KXOVER action can be in; this includes
 * being a client or a server, whose states are completely
 * separate, until they reach their final state in which
 * only success/error reporting and cleanup remains.
 */
enum kxover_progress {
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
	KXS_CLIENT_KX_SENDING,	/* Sending KX-OFFER to KXOVER server */
	KXS_CLIENT_KX_RECEIVING,/* Received KX-OFFER from KXOVER server */
	// KXS_CLIENT_KX_CHECKS,	/* Checking if the KX-OFFERs match */
	KXS_CLIENT_KEY_DERIVING,/* Key derivation in progress (uses TLS) */
	KXS_CLIENT_KEY_STORING,	/* Key construction and storage for the KDC */
				/* ...then on to KXS_SUCCESS */
	KXS_CLIENT_POST,	/* Code after any client state */
	//
	// KX Server states (already has TCP and STARTTLS)
	KXS_SERVER_PRE,		/* Code before any server state */
	KXS_SERVER_INITIALISED,	/* Server has been initialised */
	KXS_SERVER_KX_RECEIVING,/* Received KX-OFFER from KXOVER client */
	KXS_SERVER_REALMSCHECK,	/* Checking both realms against TLS certs */
	KXS_SERVER_REALM2CHECK,	/* Checking 2nd  realm  against TLS certs */
	KXS_SERVER_DNSSEC_KDC,	/* In DNSSEC query _kerberos-tls._tcp SRV */
	KXS_SERVER_HOSTCHECK,	/* Iterate SRV, compare to TLS client host */
	KXS_SERVER_KEY_DERIVING,/* Key derivation in progress (uses TLS) */
	KXS_SERVER_KEY_STORING,	/* Key construction and storage for the KDC */
	KXS_SERVER_KX_SENDING,	/* Sending KX-OFFER back to KXOVER client */
				/* ...then on to KXS_SUCCESS */
	KXS_SERVER_POST,	/* Code after any server state */
};


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
	enum kxover_progress progress_pre ;
	enum kxover_progress progress_pre2;
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


/* Quick DER packer for KX-REQ and/or KX-REP,
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
static const derwalk pack_KX_REQ [] = {
	DER_PACK_kxover_KX_REQ,
	DER_PACK_END
};
static const derwalk pack_KX_REP [] = {
	DER_PACK_kxover_KX_REP,
	DER_PACK_END
};

typedef DER_OVLY_kxover_KX_OFFER   ovly_KX_OFFER  ;
typedef DER_OVLY_kxover_KX_REQ ovly_KX_REQ;
typedef DER_OVLY_kxover_KX_REP ovly_KX_REP;

typedef DER_OVLY_rfc4120_PrincipalName pack_PrincipalName;


/* Quick DER pack/unpack instructions for KRB-ERROR.
 */
static const derwalk pack_KRB_ERROR [] = { DER_PACK_rfc4120_KRB_ERROR, DER_PACK_END };
typedef DER_OVLY_rfc4120_KRB_ERROR ovly_KRB_ERROR;


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
	struct dercursor crealm;
	struct dercursor srealm;
	cb_kxover_result cb;
	void *cbdata;
	enum kxover_progress progress;
	int last_errno;
	struct dercursor kx_recv;
	struct dercursor kx_send;
	ovly_KX_REQ kx_req_frame;
	ovly_KX_REP kx_rep_frame;
	int kxoffer_fd;
	size_t kxoffer_recvlen;
	char *kerberos_kdc_query;
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
	struct dercursor myname2 [2];
	struct iterator iter_srv;
	struct iterator iter_aaaa_a;
	struct starttls_data *tlsdata;
	time_t kx_request_time;
	time_t kx_from;
	time_t kx_till;
	kerberos_time_t kxreqtime;
	kerberos_time_t kxfrom;
	kerberos_time_t kxtill;
	der_buf_uint32_t req_kvnobuf;
	// der_buf_uint32_t rep_kvnobuf;
} kxover_t;

#define req_offer kx_req_frame.offer
#define rep_offer kx_rep_frame.offer


/* Kerberos configuration for KXOVER>
 */
static const struct kerberos_config *kxover_config;


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
// static const uint8_t const der_int_2       [] = { 0x02, 0x01, 2 };
// static const uint8_t const der_int_5       [] = { 0x02, 0x01, 5 };
// static const uint8_t const der_int_18      [] = { 0x02, 0x01, 18 };
// static const uint8_t const der_int_19      [] = { 0x02, 0x01, 19 };
// static const uint8_t const der_int_30      [] = { 0x02, 0x01, 30 };
static const uint8_t const der_int_2       [] = { 2 };
static const uint8_t const der_int_5       [] = { 5 };
static const uint8_t const der_int_18      [] = { 18 };
static const uint8_t const der_int_19      [] = { 19 };
static const uint8_t const der_int_30      [] = { 30 };
static const uint8_t const der_kstr_krbtgt [] = { 'k', 'r', 'b', 't', 'g', 't' };
static const struct dercursor dercrs_notfound     = { .derptr = (uint8_t *) der_notfound,    .derlen = sizeof(der_notfound   ) };
static const struct dercursor dercrs_int_2        = { .derptr = (uint8_t *) der_int_2,       .derlen = sizeof(der_int_2      ) };
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
printf ("DEBUG: iter_srv_next() starts the SRV iterator\n");
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
printf ("DEBUG: iter_srv_next() returns SRV cursor %d at level %d\n", it->cursor, crslvl);
				return true;
			}
		}
	} while (!it->stopped);
printf ("DEBUG: iter_srv_next() has stopped SRV iteration\n");
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
printf ("DEBUG: iter_aaaa_a_next() starts the iterator\n");
		it->cursor = 0;
		it->started = true;
		it->stopped = false;
	} else if (it->cursor >= 0) {
		it->cursor++;
printf ("DEBUG: iter_aaaa_a_next() increments the cursor to %d\n", it->cursor);
	} else {
printf ("DEBUG: iter_aaaa_a_next() decrements the cursor to %d\n", it->cursor);
		it->cursor--;
	}
	/* Test positive values against AAAA records */
	if (it->cursor >= 0) {
		if ((aaaa != NULL) && aaaa->havedata && (aaaa->data [it->cursor] != NULL)) {
printf ("DEBUG: iter_aaaa_a_next() returns an IPv6 address at %d\n", it->cursor);
			/* The cursor points to a good AAAA answer */
			return true;
		} else {
			/* The cursor points beyond the last record */
printf ("DEBUG: iter_aaaa_a_next() finished IPv6 addresses and falls back to IPv4\n");
			it->cursor = -1;
		}
	}
	/* Test negative values against A records */
	if (it->cursor < 0) {
		if ((a != NULL) && a->havedata && (a->data [-1-it->cursor] != NULL)) {
printf ("DEBUG: iter_aaaa_a_next() returns an IPv4 address at %d\n", -1-it->cursor);
			/* The cursor points to a good A answer */
			return true;
		} else {
printf ("DEBUG: iter_aaaa_a_next() stops the iterator\n");
			it->stopped = true;
		}
	}
	/* We failed and will stop now */
printf ("DEBUG: iter_aaaa_a_next() returns failure\n");
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
printf ("DEBUG: _kxover_unbound_proper() called with progress == %d\n", kxd->progress);
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
		ok = ok && result->secure;
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	}
	/* Bogus is also useful to test when DNSSEC is not enforced */
	ok = ok && !result->bogus;
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	/* Change the progress value to the post condition */
printf ("DEBUG: UNBOUND ok=%d at %s:%d\n", ok?1:0, __FILE__, __LINE__);
	if (!ok) {
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
printf ("DEBUG: cb_kxs_client_dns_aaaa_a() called with progress == %d and qtype == %d\n",
kxd->progress, (err != 0) ? -1 : result->qtype);
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
	if (!_kxover_unbound_proper (kxd, &proper_aaaa, err, kxd->ubres_aaaa)) {
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
	if (!_kxover_unbound_proper (kxd, &proper_a, err, kxd->ubres_a)) {
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
printf ("DEBUG: kx_resolve_aaaa_a() called\n");
	/* Free any prior results; these will then have succeeded */
	if (kxd->ubres_aaaa != NULL) {
printf ("DEBUG: Freeing old AAAA result\n");
		ub_resolve_free (kxd->ubres_aaaa);
		kxd->ubres_aaaa = NULL;
	}
	if (kxd->ubres_a != NULL) {
printf ("DEBUG: Freeing old A result\n");
		ub_resolve_free (kxd->ubres_a);
		kxd->ubres_a = NULL;
	}
	// Avoid repeated freeing of the resolver output
	kxd->progress = KXS_CLIENT_DNSSEC_KDC;
printf ("DEBUG: kx_resolve_aaaa_a() cleaned up old results, if any\n");
	/* Construct teh kerberos_tls_hostname from the SRV record */
	int      len  = kxd->ubres_srv->len  [kxd->iter_srv.cursor] - 6;
	uint8_t *data = kxd->ubres_srv->data [kxd->iter_srv.cursor] + 6;
	uint8_t *here = malloc (len);
	if (here == NULL) {
		kxd->last_errno = ENOMEM;
		goto bailout;
	}
	kxd->kerberos_tls_hostname = (char *) here;
	while (len-- > 0) {
		uint8_t labellen = *data++;
		assert ((labellen & 0x80) == 0x00);
		if (labellen == 0) {
			break;
		}
		memcpy (here, data, labellen);
		here += labellen;
		data += labellen;
		len  -= labellen;
		if (len > 0) {
			*here++ = '.';
		}
	}
	*here++ = '\0';
	/* Start two queries, one for AAAA and one for A */
printf ("DEBUG: Resolving AAAA and A for %s\n", kxd->kerberos_tls_hostname);
	int err6 = ub_resolve_async (kxover_unbound_ctx,
			kxd->kerberos_tls_hostname, DNS_AAAA, DNS_INET,
			kxd, cb_kxs_client_dns_aaaa_a, &kxd->ubqid_srv);
	int err4 = ub_resolve_async (kxover_unbound_ctx,
			kxd->kerberos_tls_hostname, DNS_A   , DNS_INET,
			kxd, cb_kxs_client_dns_aaaa_a, &kxd->ubqid_srv);
	/* If only one got started, cancel the whole batch */
	if (err4 != err6) {
if (err4 != 0) printf ("DEBUG: Bailing out from attempted Unbound A: %s\n", ub_strerror (err4));
if (err6 != 0) printf ("DEBUG: Bailing out from attempted Unbound AAAA: %s\n", ub_strerror (err6));
		ub_cancel (kxover_unbound_ctx,
				err4 ? kxd->ubqid_aaaa : kxd->ubqid_a);
		kxd->last_errno = ENXIO;
		goto bailout;
	}
	/* Update the state and await progress */
	kxd->progress = KXS_CLIENT_DNS_AAAA_A;
printf ("DEBUG: kx_resolve_aaaa_a() returns with two resolvers active\n");
	return;
bailout:
printf ("DEBUG: kx_resolve_aaaa_a() bails out\n");
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
printf ("DEBUG: kxover_client_connect_attempt() starts the SRV iterator\n");
		goto srvnext;
	}
	if (kxd->iter_srv.stopped) {
printf ("DEBUG: kxover_client_connect_attempt() fails on a stopped SRV iterator\n");
		kxd->last_errno = EHOSTUNREACH;
		goto bailout;
	}
	/* Move AAAA/A forward, possibly to the first entry */
	bool done;
addrnext:
	done = false;
	iter_aaaa_a_next (&kxd->iter_aaaa_a, kxd->ubres_aaaa, kxd->ubres_a);
	if (kxd->iter_aaaa_a.stopped) {
printf ("DEBUG: kxover_client_connect_attempt() ran into a stopped AAAA/A iterator\n");
		goto srvnext;
	}
	/* Fill a socket address: sa/salen */
	struct sockaddr_storage sa;
	bool ok = true;
	uint16_t srvport = ntohs (((uint16_t *) kxd->ubres_srv->data [kxd->iter_srv.cursor]) [2]);
	if (kxd->iter_aaaa_a.cursor >= 0) {
		// IPv6 address in iterator's AAAA record
		ok = ok && socket_address (AF_INET6,
				kxd->ubres_aaaa->data [   kxd->iter_aaaa_a.cursor],
				srvport,
				(struct sockaddr *) &sa);
	} else {
		// IPv4 address in iterator's A    record
		ok = ok && socket_address (AF_INET,
				kxd->ubres_a   ->data [-1-kxd->iter_aaaa_a.cursor],
				srvport,
				(struct sockaddr *) &sa);
	}
	/* Construct the socket client */
	ok = ok && socket_client ((struct sockaddr *) &sa, SOCK_STREAM, &sox);
	if (!ok) {
		/* Connection failure is just a setback; ignore and iterate */
printf ("DEBUG: socket_address() or socket_client() failure %d (%s) -- will be ignored\n", errno, strerror (errno));
		errno = 0;
		goto addrnext;
	}
	/* Setup event handling with a connect() responder as callback */
	ev_io_init (&kxd->ev_kxcnx, cb_kxs_client_connecting, sox, EV_WRITE /* TODO:FORBIDDEN: | EV_ERROR*/);
	ev_io_start (kxover_loop, &kxd->ev_kxcnx);
#if 0
	/* Finally connect to the remote's AAAA/A and the port from SRV */
	if (connect (sox, &sa, salen) < 0) {
printf ("DEBUG: Socket failure at %d\n", __LINE__);
		/* Some values in errno are caused by the deferral */
		if ((errno != EINPROGRESS) && (errno != EWOULDBLOCK) && (errno != EAGAIN)) {
			kxd->last_errno = errno;
			goto bailout;
		}
	}
#endif
	/* The connect() is in progress, done for now */
	kxd->kxoffer_fd = sox;
	kxd->progress = KXS_CLIENT_CONNECTING;
	return;
srvnext:
	/* Move on to the next SRV record */
	if (!iter_srv_next (&kxd->iter_srv, kxd->ubres_srv)) {
		/* No more options left, bail out */
printf ("DEBUG: kxover_client_connect_attempt() fails due to no more SRV records\n");
		kxd->last_errno = EHOSTUNREACH;
		goto bailout;
	}
printf ("DEBUG: kxover_client_connect_attempt() iterated to the next SRV and will now resolve it\n");
	/* continue: */
resolve:
	/* Need to lookup AAAA and A records first, which would later call this function again */
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
			kxd->kxoffer_fd, EV_READ /* TODO:FORBIDDEN | EV_ERROR*/);
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
printf ("DEBUG: cb_kxs_client_starttls() called\n");
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
	static uint8_t soll4 [4] = { 0x00, 0x00, 0x00, 0x00 };
	if (read (kxd->kxoffer_fd, ist4, 4) != 4) {
printf ("DEBUG: cb_kxs_client_starttls() received a funny number of bytes (not 4 as requested)\n");
		kxd->last_errno = EINTR;
		goto bailout;
	}
	if (memcmp (ist4, soll4, 4) != 0) {
printf ("DEBUG: cb_kxs_client_starttls() found improper response 0x%02x%02x%02x%02x\n", ist4 [0], ist4 [1], ist4 [2], ist4 [3]);
		kxd->last_errno = EPROTO;
		goto bailout;
	}
	/* Ask the Kerberos interface for the KDC name for kxd->crealm */
	struct dercursor server_kdc;
	struct dercursor client_kdc;
	server_kdc.derptr = kxd->ubres_srv->data [kxd->iter_srv.cursor] + 6;
	server_kdc.derlen = kxd->ubres_srv->len  [kxd->iter_srv.cursor] - 6;
	client_kdc = kerberos_localrealm2hostname (kxd->crealm);
	if (!der_isnonempty (&client_kdc)) {
printf ("DEBUG: cb_kxs_client_starttls() found a non-empty client_kdc\n");
		kxd->last_errno = ENOENT;
		goto bailout;
	}
	/* Both sides are now ready for TLS, so proceed */
printf ("DEBUG: cb_kxs_client_starttls() initiates TLS handshake\n");
	if (!starttls_handshake (kxd->kxoffer_fd,
			client_kdc,
			server_kdc,
			&kxd->tlsdata,
			cb_kxs_client_handshake, kxd)) {
printf ("DEBUG: cb_kxs_client_starttls() failed on TLS handshake start\n");
		kxd->last_errno = errno;
		goto bailout;
	}
printf ("DEBUG: cb_kxs_client_starttls() returns successfully, setting progress from %d to %d\n", kxd->progress, KXS_CLIENT_HANDSHAKE);
	kxd->progress = KXS_CLIENT_HANDSHAKE;
	return;
bailout:
printf ("DEBUG: cb_kxs_client_starttls() bails out\n");
	kxover_finish (kxd);
}


/* The starttls.c module has reached a verdict on the TLS handshake.
 * This is reflected in fd_new, which is <0 on error or >=0 on success.
 * When failed, we do not try elsewhere, but fail the client attempt.
 */
static void cb_kxs_client_handshake (void *cbdata, int fd_new) {
printf ("DEBUG: cb_kxs_client_handshake() called\n");
	struct kxover_data *kxd = cbdata;
	/* Test if the TLS handshake succeeded */
	if (fd_new < 0) {
		goto bailout;
	}
	/* Check the realm names against the TLS certificates */
printf ("DEBUG: cb_kxs_client_handshake() calls kx_start_realmscheck()\n");
	if (!kx_start_realmscheck (kxd)) {
		/* kxd->last_errno has been set */
		goto bailout;
	}
	/* Continue into realm checking */
printf ("DEBUG: cb_kxs_client_handshake() returns after changing progress from %d to %d\n", kxd->progress, KXS_CLIENT_REALMSCHECK);
	kxd->progress = KXS_CLIENT_REALMSCHECK;
	return;
bailout:
printf ("DEBUG: cb_kxs_client_handshake() bails out without... saying a thing?!?  [TODO]\n");
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
		starttls_handshake_cancel (kxd->tlsdata);
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
printf ("cb_kxs_either_realmscheck() called with success = %d and last_errno = %d\n", success, kxd->last_errno);
	/* Ensure success */
	if (!success) {
		kxd->last_errno = EACCES;
		/* During the 2nd, we will goto bailout */
printf ("cb_kxs_either_realmscheck() is not a success, and signals EACCES = %d\n", EACCES);
	}
	/* Hold off activity during the first callback (of two) */
	if (kxd->progress == KXS_CLIENT_REALMSCHECK) {
		/* Change progress to "seen one, one more to come" */
printf ("DEBUG: cb_kxs_either_realmscheck() has seen 1/2 realms for the client\n");
		kxd->progress = KXS_CLIENT_REALM2CHECK;
		return;
	} else if (kxd->progress == KXS_SERVER_REALMSCHECK) {
printf ("DEBUG: cb_kxs_either_realmscheck() has seen 1/2 realms for the server\n");
		/* Change progress to "seen one, one more to come" */
		kxd->progress = KXS_SERVER_REALM2CHECK;
		return;
	}
	/* Given two checked realms, we look for last_errno */
	if (kxd->last_errno == EACCES) {
printf ("DEBUG: cb_kxs_either_realmscheck() found last_errno set\n");
		goto bailout;
	}
	/* Given two correct realms, proceed to the subsequent phase */
	if (kxd->progress == KXS_SERVER_REALM2CHECK) {
printf ("DEBUG: cb_kxs_either_realmscheck() has seen 2/2 realms for the server\n");
		/* Continue into DNS, asking for the client KDC's SRV records */
		if (!kx_start_dnssec_kdc (kxd, kxd->crealm)) {
			/* kdc->last_errno was set by kx_start_dnssec_kdc() */
			goto bailout;
		}
		kxd->progress = KXS_SERVER_DNSSEC_KDC;
	} else if (kxd->progress == KXS_CLIENT_REALM2CHECK) {
printf ("DEBUG: cb_kxs_either_realmscheck() has seen 2/2 realms for the client\n");
		/* Continue into sending KX-OFFER */
		kx_start_client_kx_sending (kxd, false);
		kxd->progress = KXS_CLIENT_KX_SENDING;
	} else {
		/* Fail with the message that mentions both acceptable states */
printf ("DEBUG: cb_kxs_either_realmscheck() with unexpected progress == %d\n", kxd->progress);
		//A BIT HEAVY// assert ((kxd->progress == KXS_CLIENT_REALM2CHECK) || (kxd->progress == KXS_SERVER_REALM2CHECK));
		kxd->last_errno = ENOSYS;
		goto bailout;
	}
	return;
bailout:
printf ("DEBUG: cb_kxs_either_realmscheck() bails out\n");
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
static void kx_start_client_kx_sending (struct kxover_data *kxd, bool _refresh_only) {
	uint8_t *kxname2pack = NULL;
	uint8_t *myname2pack = NULL;
	static const derwalk pack_name2 [] = {
		DER_PACK_ENTER | DER_TAG_SEQUENCE,
		DER_PACK_STORE | DER_TAG_GENERALSTRING,
		DER_PACK_STORE | DER_TAG_GENERALSTRING,
		DER_PACK_END };
printf ("DEBUG: kx_start_client_kx_sending() called\n");
	//
	// First look at the wall clock...
	time_t now;
	now = time (NULL);
	if (now == (time_t) -1) {
		/* errno is set to EOVERFLOW */
		goto bailout;
	}
	//
	// Create basic setup for the kx_req_frame
	kxd->kx_req_frame.pvno = dercrs_int_5;
	kxd->kx_req_frame.msg_type = dercrs_int_18;
	//
	// Set kxd->req_offer.request_time to "now"
	kxd->kx_request_time = now;
	if (!kerberos_time_set (now, kxd->kxreqtime)) {
		goto bailout;
	}
	kxd->req_offer.request_time.derptr = kxd->kxreqtime;
	kxd->req_offer.request_time.derlen = KERBEROS_TIME_STRLEN;
printf ("DEBUG: req_offer->kxreqtime = %s\n", kxd->kxreqtime);
	//
	// Fill the salt with random bytes
	if (!kerberos_prng (kxd->salt, sizeof (kxd->salt))) {
		kxd->last_errno = errno;
		goto bailout;
	}
	kxd->req_offer.salt.derptr = kxd->salt;
	kxd->req_offer.salt.derlen = sizeof (kxd->salt);
printf ("DEBUG: req_offer->salt = %02x %02x...%02x %02x\n", kxd->salt [0], kxd->salt [1], kxd->salt [sizeof (kxd->salt)-2], kxd->salt [sizeof (kxd->salt)-1]);
	//
	// Fill in kx_name with the ticket PrincipalName and Realm
	kxd->req_offer.kx_name.realm = kxd->crealm;
	kxd->req_offer.kx_name.principalName.name_type = dercrs_int_2;
	kxd->kxname2 [0] = dercrs_kstr_krbtgt;
	kxd->kxname2 [1] = kxd->srealm;
	size_t kxname2len = der_pack (pack_name2, kxd->kxname2, NULL);
	kxname2pack = malloc (kxname2len);
	if (kxname2pack == NULL) {
		kxd->last_errno = ENOMEM;
		goto bailout;
	}
	der_pack (pack_name2, kxd->kxname2, kxname2pack + kxname2len);
	kxd->req_offer.kx_name.principalName.name_string.wire.derptr = kxname2pack;
	kxd->req_offer.kx_name.principalName.name_string.wire.derlen = kxname2len;
printf ("DEBUG: req_offer->kx_name = %.*s/%.*s@%.*s\n", kxd->kxname2[0].derlen, kxd->kxname2[0].derptr, kxd->kxname2[1].derlen, kxd->kxname2[1].derptr, kxd->srealm.derlen, kxd->srealm.derptr);
	//
	//TODO//FILL// kxd->req_offer.kvno -- for now, MMDDS with S==0
	uint32_t kvno = 3052;
	kxd->req_offer.kvno = der_put_uint32 (kxd->req_kvnobuf, kvno);
	//
	// Set the enctypes to the ones allowed locally
	//TODO//FILL// kxd->req_offer.etypes
	//
	// Set kxd->req_offer.from to "now", sharing space with kxd->kxreqtime
	kxd->kx_from = now;
	if (!kerberos_time_set (now, kxd->kxfrom)) {
		goto bailout;
	}
	kxd->req_offer.from.derptr = kxd->kxfrom;
	kxd->req_offer.from.derlen = KERBEROS_TIME_STRLEN;
printf ("DEBUG: req_offer->kxfrom = %s\n", kxd->kxfrom);
	//
	// Set kxd->req_offer.till to "now" + configured #days
	time_t then = now + kxover_config->crossover_lifedays * 24 * 3600;
	if (then < now) {
		errno = EOVERFLOW;
		goto bailout;
	}
	kxd->kx_till = then;
	if (!kerberos_time_set (then, kxd->kxtill)) {
		goto bailout;
	}
	kxd->req_offer.till.derptr = kxd->kxtill;
	kxd->req_offer.till.derlen = KERBEROS_TIME_STRLEN;
printf ("DEBUG: req_offer->kxtill = %s\n", kxd->kxtill);
	//
	//TODO//FILL// kxd->req_offer.max_uses (OPTIONAL)
	//
	// Set kxd->req_offer.my_name to krbtgt/CLIENT.REALM@CLIENT.REALM
	kxd->req_offer.my_name.realm = kxd->crealm;
	kxd->req_offer.my_name.principalName.name_type = dercrs_int_2;
	kxd->myname2 [0] = dercrs_kstr_krbtgt;
	kxd->myname2 [1] = kxd->crealm;
	size_t myname2len = der_pack (pack_name2, kxd->myname2, NULL);
	myname2pack = malloc (myname2len);
	if (myname2pack == NULL) {
		kxd->last_errno = ENOMEM;
		goto bailout;
	}
	der_pack (pack_name2, kxd->myname2, myname2pack + myname2len);
	kxd->req_offer.my_name.principalName.name_string.wire.derptr = myname2pack;
	kxd->req_offer.my_name.principalName.name_string.wire.derlen = myname2len;
	//
	//TODO//FILL// kxd->req_offer.extensions (PREPACK, IF ANY)
	//
	// Map the fields in req_offer to a DER message kx_send
printf ("DEBUG: Packing as DER...\n");
	size_t   reqlen = der_pack (pack_KX_REQ, (dercursor *) &kxd->kx_req_frame, NULL);
printf ("DEBUG: Precomputed DER size is %d\n", reqlen);
	uint8_t *reqptr = malloc (reqlen);
	if (reqptr == NULL) {
		errno = ENOMEM;
		goto bailout;
	}
	der_pack (pack_KX_REQ, (dercursor *) &kxd->kx_req_frame, reqptr + reqlen);
	free (myname2pack);
	free (kxname2pack);
	kxname2pack = NULL;
	myname2pack = NULL;
	kxd->kx_send.derlen = reqlen;
	kxd->kx_send.derptr = reqptr;
#ifdef DEBUG
int fd = open ("/tmp/kx_req.der", O_WRONLY | O_CREAT | O_TRUNC, 0644);
assert (write (fd, reqptr, reqlen) == reqlen);
	// TODO:valgrind: invalid file descriptor -1 in write
	// TODO:valgrind: Process terminating with default action of signal 6 (SIGABRT)
close (fd);
printf ("DEBUG: Written KX_REQ to /tmp/kx_req.der\n");
#endif
	//
	// Now send the kx_send message over kxoffer_fd
	if (send (kxd->kxoffer_fd, reqptr, reqlen, 0) != reqlen) {
		/* Close the socket and let event handler signal it */
		/* Note: We could send with callbacks, if need be */
		close (kxd->kxoffer_fd);
		kxd->kxoffer_fd = -1;
		return;
	}
	//
	// Register the next callback function to collect the response
	ev_io_init (&kxd->ev_kxcnx, cb_kxs_client_kx_receiving, kxd->kxoffer_fd, EV_READ /* TODO:FORBIDDEN; | EV_ERROR */);
	ev_io_start (kxover_loop, &kxd->ev_kxcnx);
	kxd->progress = KXS_CLIENT_KX_RECEIVING;
	return;
bailout:
printf ("DEBUG: kx_start_client_kx_sending() bails out\n");
	kxd->last_errno = errno;
	kxover_finish (kxd);
	if (myname2pack != NULL) {
		free (myname2pack);
	}
	if (kxname2pack != NULL) {
		free (kxname2pack);
	}
}


/* Callback for incoming traffic from the server, to be stored
 * as KX-OFFER in kxd->kx_recv, possibly arriving in parts.  The
 * first part must be at least 5 bytes to be considered, however.
 */
static void cb_kxs_client_kx_receiving (EV_P_ ev_io *evt, int revents) {
printf ("DEBUG: cb_kxs_client_kx_receiving() called\n");
	struct kxover_data *kxd =
		(struct kxover_data *) (
			((uint8_t *) evt) -
				offsetof (struct kxover_data, ev_kxcnx));
	/* Bail out immediately when there are connection problems */
	if (revents & EV_ERROR) {
		kxd->last_errno = EIO;
		goto bailout;
	}
	/* First collect and interpret the 4 length bytes */
	if (kxd->kx_recv.derptr == NULL) {
		uint8_t buf4 [4];
		uint8_t tag;
		size_t  len;
		uint8_t hlen;
		//TODO//NOT// dercursor sofar;
		if (recv (kxd->kxoffer_fd, buf4, 4, 0) != 4) {
printf ("DEBUG: Expected 4 bytes of packet length\n");
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
	/* Compare the outer DER length and unpack the KX-REP */
	struct dercursor inicrs = kxd->kx_recv;
	uint8_t tag;
	size_t len;
	uint8_t hlen;
	if ((der_header (&inicrs, &tag, &len, &hlen) != 0) || (len+hlen != kxd->kx_recv.derlen)) {
printf ("DER header wrong: tag 0x%02x, hlen=%d, len=%d, totalen %d\n", tag, hlen, len, kxd->kx_recv.derlen);
		/* Error analysing the header */
		kxd->last_errno = EBADMSG;
		goto bailout;
	}
	if (!kxoffer_unpack (kxd->kx_recv, dercrs_int_19, &kxd->rep_offer)) {
printf ("DER message of KX-OFFER failed to unpack: %d (%s)\n", errno, strerror (errno));
		kxd->last_errno = errno;
		goto bailout;
	}
	/* Analyse the data and compare req_offer and rep_offer */
	if (der_cmp (kxd->req_offer.request_time, kxd->rep_offer.request_time) != 0) {
		/* Request Time in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	if (der_cmp (kxd->req_offer.kx_name.realm, kxd->rep_offer.kx_name.realm) != 0) {
		/* Realm in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	if (der_cmp (kxd->req_offer.kx_name.principalName.name_type, kxd->rep_offer.kx_name.principalName.name_type) != 0) {
		/* name_type in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	if (der_cmp (*(dercursor *) &kxd->req_offer.kx_name.principalName.name_string,
	             *(dercursor *) &kxd->rep_offer.kx_name.principalName.name_string) != 0) {
		/* name_string (SEQUENCE OF, so we get them all in one go) in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	struct dercursor service_realm;
	if (!_parse_service_principalname (2, &kxd->req_offer.kx_name.principalName, NULL, &service_realm)) {
printf ("cb_kxs_client_kx_receiving() found invalid PrincipalName, last_errno := %d (%s)\n", errno, strerror (errno));
		kxd->last_errno = errno;
		goto bailout;
	}
	//TODO// regexp: all-lowercase requirement
	if (der_cmp (service_realm, kxd->kxname2[1]) != 0) {
		/* Service hostname in KX-REQ and KX-REP did not match */
		goto bailout_EPROTO;
	}
	/* End this callback, and continue with key derivation */
	if (!kx_start_key_deriving (kxd)) {
		/* kxd->last_errno is set by kx_start_key_deriving() */
		/* ev_io_stop() was already called */
		goto bailout_stopped;
	}
	kxd->progress = KXS_CLIENT_KEY_DERIVING;
printf ("DEBUG: cb_kxs_client_kx_receiving() returns with progress == %d == KXS_CLIENT_KEY_DERIVING\n", kxd->progress);
	return;
bailout_EPROTO:
	errno = EPROTO;
	/* ...and continue: */
bailout:
	ev_io_stop (EV_A_ evt);
	/* ...and continue: */
bailout_stopped:
printf ("DEBUG: cb_kxs_client_kx_receiving() bailout\n");
	kxover_finish (kxd);
}


/* Process an Unbound callback, presumably in response to
 * a query that we posted from here.  We delegate control
 * to Unbound's processor, which will deliver via query
 * callbacks.
 */
static void _cb_kxover_unbound (EV_P_ ev_io *_evt, int _revents) {
printf ("DEBUG: _cb_kxover_unbound() called -- passing on to ub_process()\n");
	ub_process (kxover_unbound_ctx);
printf ("DEBUG: _cb_kxover_unbound() ended  -- finished with ub_process()\n");
}


void TODO_cb_ignore (void *cbdata, bool ok) {
printf ("DEBUG: TODO_cb_ignore (cbdata, ok=%d)\n", ok);
}

/* Start key determination and storage in the KDC database.
 * On a KXOVER server, this runs before responding so the KDC
 * is sure to have the key; on a KXOVER client, this runs
 * after receiving a response because that information is
 * needed to perform these computations.  After this call,
 * progress should be set to KXS_x_KEY_DERIVING.
 */
static bool kx_start_key_deriving (struct kxover_data *kxd) {
printf ("DEBUG: kx_start_key_deriving() called\n");
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
printf ("DEBUG: Calling starttls_export_key with no_ctxval [.ptr=NULL, .len=0]\n");
	if (!starttls_export_key (label, no_ctxval,
			keylen, key,
			kxd->tlsdata,
			TODO_cb_ignore, kxd)) {
printf ("DEBUG: Failure from starttls_export_key, errno = %d (%s)\n", errno, strerror (errno));
		kxd->last_errno = errno;
		goto bailout;
	}
printf ("DEBUG: kx_start_key_deriving() finished\n");
	return true;
bailout:
printf ("DEBUG: kx_start_key_deriving() bails out\n");
	kxover_finish (kxd);
	return false;
}


/* Unpack an incoming KX-OFFER message, contained in either
 * KX-REQ (msg_type 18) or KX-REP (msg_type 19).
 * Store the resulting dercrs values in outvars.
 *
 * Return true on success, or false with errno set on failure.
 */
static bool kxoffer_unpack (dercursor msg, dercursor msg_type,
			ovly_KX_OFFER *outvars) {
	/* First unpack the message surroundings of KX-RE? */
	struct dercursor msg_ovly [3];  /* 5, msg-type, KX-OFFER */
	if (der_unpack (&msg, pack_msg_shallow, msg_ovly, 1) != 0) {
		errno = EBADMSG;
		goto bailout;
	}
	/* Verify the pvno and msg-type fields */
	if (der_cmp (msg_ovly [0], dercrs_int_5) != 0) {
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
	if (der_unpack (&msg, pack_KX_OFFER, (dercursor *) outvars, 1) != 0) {
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
	struct dercursor der0 = * (dercursor *) &princname->name_string;         /* copy */
int printf (const char *__restrict __format, ...);
printf ("DEBUG: der0     # %d\tat %s:%d\n", der0.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_enter (&der0));
printf ("DEBUG: der0     # %d\tat %s:%d\n", der0.derlen, __FILE__, __LINE__);
	struct dercursor der1 = der0;                 /* copy */
printf ("DEBUG: der0,1   # %d,%d\tat %s:%d\n", der0.derlen, der1.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_skip  (&der1));
printf ("DEBUG: der0,1   # %d,%d\tat %s:%d\n", der0.derlen, der1.derlen, __FILE__, __LINE__);
	struct dercursor der2 = der1;                 /* copy */
printf ("DEBUG: der0,1,2 # %d,%d,%d\tat %s:%d\n", der0.derlen, der1.derlen, der2.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_skip  (&der2));
printf ("DEBUG: der0,1,2 # %d,%d,%d\tat %s:%d\n", der0.derlen, der1.derlen, der2.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_focus (&der0));
printf ("DEBUG: der0,1,2 # %d,%d,%d\tat %s:%d\n", der0.derlen, der1.derlen, der2.derlen, __FILE__, __LINE__);
	ok = ok && (0 == der_focus (&der1));
printf ("DEBUG: der0,1,2 # %d,%d,%d\tat %s:%d\n", der0.derlen, der1.derlen, der2.derlen, __FILE__, __LINE__);
	ok = ok &&  der_isnonempty (&der0);
	ok = ok &&  der_isnonempty (&der1);
	ok = ok && !der_isnonempty (&der2);
	if (!ok) {
		goto bad_message;
	}
	bool is_krbtgt = (der_cmp (der0, dercrs_kstr_krbtgt) == 0);
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
	if (out_label0 != NULL) {
		*out_label0 = der0;
	}
	if (out_label1 != NULL) {
		*out_label1 = der1;
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
printf ("DEBUG: kx_start_dnssec_kdc() called for %.*s\n", realm_name.derlen, (char *) realm_name.derptr);
	/* Construct the server realm name with "_kerberos-tls._tcp." prefixed */
	char *kerberos_kdc_query = malloc (19 + realm_name.derlen + 1);
	if (kerberos_kdc_query == NULL) {
		/* Out of memory */
		kxd->last_errno = ENOMEM;
		goto bailout;
	}
	kxd->kerberos_kdc_query = kerberos_kdc_query;
	memcpy (kerberos_kdc_query   , "_kerberos-tls._tcp.", 19);
	memcpy (kerberos_kdc_query+19, realm_name.derptr, realm_name.derlen);
	kerberos_kdc_query [19+realm_name.derlen] = '\0';
printf ("DEBUG: SRV query for KDC at kerberos_kdc_query == \"%s\"\n", kerberos_kdc_query);
	/* Continue to look for the server realm's KDC address */
	int ub_errno = ub_resolve_async (kxover_unbound_ctx,
			kerberos_kdc_query, DNS_SRV, DNS_INET,
			kxd, cb_kxs_either_dnssec_kdc, &kxd->ubqid_srv);
	if (ub_errno != 0) {
		//TODO// Harvest information from ub_strerror (ub_errno)
printf ("DEBUG: Bailing out from attempted Unbound SRV: %s\n", ub_strerror (ub_errno));
		kxd->last_errno = ENXIO;
		goto bailout;
	}
	/* Success */
	return true;
bailout:
printf ("DEBUG: kx_start_dnssec_kdc() bailout with kxd->last_errno = %d\n", kxd->last_errno);
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
			void *cbdata,
			int err, struct ub_result *result) {
	struct kxover_data *kxd = cbdata;
printf ("DEBUG: cb_kxs_either_dnssec_kdc() called with progress == %d\n", kxd->progress);
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
printf ("DEBUG: Processing SRV records as potentials for key derivation in cb_kxs_either_dnssec_kdc() for the server\n");
		/* Signal the new state, even if we currently don't wait in it */
		kxd->progress = KXS_SERVER_HOSTCHECK;
		/* On a server, check the host name against the certificate */
		iter_reset (&kxd->iter_srv);
		while (iter_srv_next (&kxd->iter_srv, kxd->ubres_srv)) {
			struct dercursor hostname;
			hostname.derptr = kxd->kerberos_tls_hostname;
			hostname.derlen = strlen (hostname.derptr);
			if (starttls_remote_hostname_check_certificate (
					hostname, kxd->tlsdata)) {
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
printf ("DEBUG: Calling kxover_client_connect_attempt() from cb_kxs_either_dnssec_kdc() for the client\n");
		/* On a client, work towards a connected socket */
		kxover_client_connect_attempt (kxd);
		return;
	} else {
printf ("DEBUG: Failing because cb_kxs_either_dnssec_kdc() acts for neither client nor server\n");
		/* Trigger an error with an assertion that cannot succeed */
		assert ((kxd->progress == KXS_SERVER_DNSSEC_KDC) || (kxd->progress == KXS_CLIENT_DNSSEC_KDC));
		return;
}
bailout:
printf ("DEBUG: cb_kxs_either_dnssec_kdc() bails out\n");
	kxover_finish (kxd);
	return;
}


/* Process an incoming _kerberos TXT record for the KXOVER client.
 * This is a callback from Unbound, installed in kxover_client().
 */
static void cb_kxs_client_dnssec_realm (
			void *cbdata,
			int err, struct ub_result *result) {
	struct kxover_data *kxd = cbdata;
printf ("DEBUG: cb_kxs_client_dnssec_realm() called with progress == %d\n", kxd->progress);
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
printf ("DEBUG: cb_kxs_client_dnssec_realm() bailout with kxd->last_errno = %d\n", kxd->last_errno);
	kxover_finish (kxd);
	return;
}


/* Initialise the kxover.c module, setting the event loop it
 * should use.
 *
 * When opt_etc_hosts_file is not NULL, it is configured as
 * Unbound's source of ip/host mappings to report unsecurely.
 *
 * Return true on succes, or false with errno set on failure.
 */
bool kxover_init (EV_P_ char *dnssec_rootkey_file, char *opt_etc_hosts_file) {
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
	if (opt_etc_hosts_file != NULL) {
		if (ub_ctx_hosts (kxover_unbound_ctx, opt_etc_hosts_file)) {
			errno = ECONNREFUSED;
			goto teardown_unbound;
		}
	}
	int fd = ub_fd (kxover_unbound_ctx);
	if (fd < 0) {
		/* Not sure if libunbound sets errno */
		errno = ECONNREFUSED;
		goto teardown_unbound;
	}
	/* Retrieve the Kerberos configuration */
	kxover_config = kerberos_config ();
	/* Initialise the event loop, with Unbound service */
	kxover_loop = loop;
	ev_io_init (&kxover_unbound_watcher, _cb_kxover_unbound, fd, EV_READ /* TODO:FORBIDDEN | EV_ERROR*/);
	ev_io_start (EV_A_ &kxover_unbound_watcher);
	return true;
teardown_unbound:
	ub_ctx_delete (kxover_unbound_ctx);
	kxover_unbound_ctx = NULL;
	return false;
}


/* Clean up resources used by kxover.  All running processes must have
 * ended before this is called.
 */
void kxover_fini (void) {
	ub_ctx_delete (kxover_unbound_ctx);
	kxover_unbound_ctx = NULL;
}


/* Having classified a frame from upstream as Kerberos,
 * interpret the read Kerberos data and see if it should be
 * handled as KXOVER, or passed to the downstream.
 *
 * This function always returns a meaningful result.
 * Possible return values are TCPKRB5_PASS, _KXOVER_REQ as
 * well as _ERROR.
 */
tcpkrb5_t kxover_classify_kerberos_down (struct dercursor krb) {
	uint8_t tag;
	size_t intlen;
	uint8_t hdrlen;
	struct dercursor krb2 = krb;
	if (der_header (&krb2, &tag, &intlen, &hdrlen) != 0) {
		return TCPKRB5_ERROR;
	}
	if (hdrlen + intlen != krb.derlen) {
printf ("DEBUG: Outside DER length is incorrect\n");
		return TCPKRB5_ERROR;
	}
	switch (tag) {
	case APPTAG_KXOVER_REQ:
printf ("DEBUG: Recognised APPTAG_KXOVER_REQ\n");
		return TCPKRB5_KXOVER_REQ;
	case APPTAG_KXOVER_REP:
printf ("DEBUG: Recognised APPTAG_KXOVER_REP\n");
		return TCPKRB5_ERROR;
	case APPTAG_KRB_ERROR:
printf ("DEBUG: Recognised APPTAG_KRB_ERROR\n");
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
tcpkrb5_t kxover_classify_kerberos_up (struct dercursor krb) {
	uint8_t tag;
	size_t intlen;
	uint8_t hdrlen;
	if (der_header (&krb, &tag, &intlen, &hdrlen) != 0) {
		return TCPKRB5_ERROR;
	}
	if (hdrlen + intlen != krb.derlen) {
		return TCPKRB5_ERROR;
	}
	switch (tag) {
	case APPTAG_KRB_ERROR:
		if (der_walk (&krb, krberror2code) != 0) {
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
 * The server borrows the ownership of kx_req_frame
 * for the duration of its processing, that data is
 * assumed to be stable until the callback.
 */
struct kxover_data *kxover_server (cb_kxover_result cb, void *cbdata,
			struct dercursor kx_req_frame, int kxoffer_fd) {
	assert (kx_req_frame.derptr != NULL);
	assert (kx_req_frame.derlen > 10);
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
	kxd->kx_recv = kx_req_frame;
	if (!kxoffer_unpack (kx_req_frame, dercrs_int_18, &kxd->req_offer)) {
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
printf ("DEBUG: _kxover_server_cleanup() called with progress == %d\n", kxd->progress);
	//TODO// Stop event watchers, cleanup
	;
printf ("DEBUG: _kxover_server_cleanup() complete\n", kxd->progress);
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
struct kxover_data *kxover_client (cb_kxover_result cb, void *cbdata,
			struct dercursor client_realm, struct dercursor service_realm) {
printf ("DEBUG: kxover_client() is called for krbtgt/%.*s@%.*s\n", service_realm.derlen, (char *) service_realm.derptr, client_realm.derlen, (char *) client_realm.derptr);
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
	ev_timer_init (&kxd->ev_timeout, cb_kxover_timeout, 60.0, 0.0);
	kxd->progress = KXS_CLIENT_INITIALISED;
	/* Initiate activity with a lookup of the realm with _kerberos TXT */
	kerberos_REALM = malloc (10 + service_realm.derlen + 1);
	if (kerberos_REALM == NULL) {
		errno = ENOMEM;
		goto bailout;
	}
	memcpy (kerberos_REALM     , "_kerberos.", 10);
	memcpy (kerberos_REALM + 10, service_realm.derptr, service_realm.derlen);
	kerberos_REALM [10 + service_realm.derlen] = '\0';
printf ("DEBUG: kerberos_REALM == \"%s\"\n", kerberos_REALM);
	//TODO//UNUSED// kxd->kerberos_REALM = kerberos_REALM;
printf ("DEBUG: Requesting async DNS with progress == %d\n", kxd->progress);
	int ub_errno = ub_resolve_async (kxover_unbound_ctx,
			kerberos_REALM, DNS_TXT, DNS_INET,
			kxd, cb_kxs_client_dnssec_realm, &kxd->ubqid_txt);
	if (ub_errno != 0) {
printf ("DEBUG: Bailing out from attempted Unbound TXT: %s\n", ub_strerror (ub_errno));
		errno = ENXIO;
		goto bailout;
	}
	/* Indicate that the realm lookup is in progress */
	/* Note: Unbound continues in the event loop */
	kxd->progress = KXS_CLIENT_DNSSEC_REALM;
printf ("DEBUG: Returning opaque kxover_data with progress == %d\n", kxd->progress);
	return kxd;
bailout:
	/* Cleanup processing without callback */
	_kxover_client_cleanup (kxd);
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
printf ("DEBUG: _kxover_client_cleanup() called with progress == %d\n", kxd->progress);
	switch (kxd->progress) {
	case KXS_CLIENT_KEY_STORING:
	case KXS_CLIENT_KEY_DERIVING:
	case KXS_CLIENT_KX_RECEIVING:
		if (kxd->kx_recv.derptr) {
			free (kxd->kx_recv.derptr);
			kxd->kx_recv.derptr = NULL;
		}
		kxd->kx_recv.derlen = 0;
	case KXS_CLIENT_KX_SENDING:
		if (kxd->kx_send.derptr) {
			free (kxd->kx_send.derptr);
			kxd->kx_send.derptr = NULL;
		}
		kxd->kx_send.derlen = 0;
	case KXS_CLIENT_REALM2CHECK:
	case KXS_CLIENT_REALMSCHECK:
		;
	case KXS_CLIENT_HANDSHAKE:
		if (kxd->tlsdata != NULL) {
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
printf ("DEBUG: client Unbound free AAAA\n");
			ub_resolve_free (kxd->ubres_aaaa);
		} else {
printf ("DEBUG: client Unbound cancel AAAA\n");
			ub_cancel (kxover_unbound_ctx, kxd->ubqid_aaaa);
		}
		if (kxd->ubres_a != NULL) {
printf ("DEBUG: client Unbound free A\n");
			ub_resolve_free (kxd->ubres_a);
		} else {
printf ("DEBUG: client Unbound cancel A\n");
			ub_cancel (kxover_unbound_ctx, kxd->ubqid_a);
		}
	case KXS_CLIENT_DNSSEC_KDC:
		if (kxd->ubres_srv != NULL) {
printf ("DEBUG: client Unbound free SRV\n");
			ub_resolve_free (kxd->ubres_srv);
		} else {
printf ("DEBUG: client Unbound cancel SRV\n");
			ub_cancel (kxover_unbound_ctx, kxd->ubqid_srv);
		}
		if (kxd->kerberos_kdc_query != NULL) {
			free (kxd->kerberos_kdc_query);
			kxd->kerberos_kdc_query = NULL;
		}
	case KXS_CLIENT_DNSSEC_REALM:
		if (kxd->ubres_txt != NULL) {
printf ("DEBUG: client Unbound free TXT\n");
			ub_resolve_free (kxd->ubres_txt);
		} else {
printf ("DEBUG: client Unbound cancel TXT\n");
			ub_cancel (kxover_unbound_ctx, kxd->ubqid_txt);
		}
		if (kxd->kerberos_tls_hostname != NULL) {
			free (kxd->kerberos_tls_hostname);
			kxd->kerberos_tls_hostname = NULL;
		}
	case KXS_CLIENT_INITIALISED:
		//TODO:UNUSED// if (kxd->kerberos_REALM != NULL) {
		//TODO:UNUSED// 	free (kxd->kerberos_REALM);
		//TODO:UNUSED// 	kxd->kerberos_REALM = NULL;
		//TODO:UNUSED// }
		;
	default:
		;
	}
	//TODO// Stop event watchers, cleanup
	;
printf ("DEBUG: _kxover_client_cleanup() complete\n");
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
	enum kxover_progress progress = kxd->progress;
	if        ((progress > KXS_CLIENT_PRE ) &&
	           (progress < KXS_CLIENT_POST)) {
		_kxover_client_cleanup (kxd);
	} else if ((progress > KXS_SERVER_PRE ) &&
	           (progress < KXS_SERVER_POST)) {
		_kxover_server_cleanup (kxd);
	}
}
void kxover_finish (struct kxover_data *kxd) {
printf ("DEBUG: kxover_finish() called with progress == %d and last_errno == %d (%s)\n", kxd->progress, kxd->last_errno, strerror (kxd->last_errno));
	/* First of all, disarm the timeout timer */
	ev_timer_stop (kxover_loop, &kxd->ev_timeout);
	/* Now record the current progress, used later */
	enum kxover_progress orig_progress = kxd->progress;
	/* Cleanup client or server specifics, if any */
	_kxover_cleanup (kxd);
	/* If not done yet, run the callback to report errno ECANCELED */
	if ((orig_progress != KXS_CALLBACK) && (orig_progress != KXS_CLEANUP)) {
		kxd->progress = KXS_CALLBACK;
printf ("DEBUG: Informing callback about kxover results\n");
		kxd->cb (kxd->cbdata, kxd->last_errno, kxd->crealm, kxd->srealm);
printf ("DEBUG: Informed  callback about kxover results\n");
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
printf ("DEBUG: kxover_finish() call complete\n");
}
void kxover_cancel (struct kxover_data *kxd) {
printf ("DEBUG: kxover_cancel() called\n");
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
			cb_kxover_result cb, void *cbdata,
			struct dercursor krbdata) {
int printf (const char *__restrict __format, ...);
	ovly_KRB_ERROR fields;
	der_unpack (&krbdata, pack_KRB_ERROR, (struct dercursor *) &fields, 1);
	if (der_cmp (fields.pvno, dercrs_int_5) != 0) {
		errno = EPROTO;
printf ("DEBUG: kvno != 5\n");
		return NULL;
	}
	if (der_cmp (fields.msg_type, dercrs_int_30) != 0) {
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
static void cb_kxover_timeout (EV_P_ ev_timer *evt, int _revents) {
	struct kxover_data *kxd =
		(struct kxover_data *) (
			((uint8_t *) evt) -
				offsetof (struct kxover_data, ev_timeout));
printf ("DEBUG: cb_kxover_timeout() called with progress == %d\n", kxd->progress);
	kxd->last_errno = ETIMEDOUT;
	kxover_finish (kxd);
}


