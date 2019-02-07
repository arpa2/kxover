/* TCP/TLS wrapper for Kerberos -- including local handling logic.
 *
 * Routines to read/write TCP data blocks, as well as flags.  This
 * handles the STARTTLS wrapper to a plain TCP backend.  TLS is
 * assumed to be mostly useful for KXOVER at the moment, though it
 * might also be used by paranoid clients to protect their privacy.
 *
 * The backend is assumed to be a nearby TCP connection, saving us
 * the trouble of resends.  This may be used as a bump in the wire
 * towards the KDC.  There are optional extensions that would
 * incorporate rate limiting here; this would also make sense for
 * KXOVER, which ought to be a low-traffic pattern of the order of
 * the number of realms on client KDC and service KDC multiplied,
 * divided by the agreed-upon valid time for crossover tickets.
 *
 * This implementation handles individual queries over one TCP stream
 * in lock-step, that is cyclic request->handle->response treatment.
 * A separate backend TCP connection is made for every incoming TCP
 * connection.  This is probably a point of future optimisation, as
 * the KDC could respond out-of-order if it wanted to.
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

#include <quick-der/api.h>



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


/* DER code to be held in the KRB-ERROR error-code for NOTFOUND.
 */
static const uint8_t der_notfound[] = { 0x07 };


/* The various ways of responding to a len_flags value from upstream.
 */
typedef enum tcpflags {
	TCPFLAGS_KERBEROS = 0,	/* Treat as a Kerberos message */
	TCPFLAGS_PROBE    = 1,	/* Downstream probing (flags 0) */
	TCPFLAGS_STARTTLS = 2,	/* Switch the connection to TLS */
	TCPFLAGS_ERROR    = -1	/* The len_flags value is an error */
} tcpflags_t;


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


/* The sockaddr for the KDC is address ::1 port 88.
 */
struct sockaddr_in6 kdc_sockaddr = {
	.sin6_family = AF_INET6,
	.sin6_port = htons (88),
	.sin6_addr = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
};


/* Return a TCP connection to the KDC.
 *
 * Return a file descriptor on success, -1 on failure with errno set.
 */
int tcp_connect_kdc (void) {
	int sox;
	sox = socket (AF_INET6, SOCK_STREAM, 0);
	if (sox >= 0) {
		if (connect (sox, &kdc_sockaddr, sizeof (kdc_sockaddr)) != 0) {
			close (sox);
			sox = -1;
		}
		
	}
	return -1;
}


/* Read a given number of bytes of data from the input stream.
 * This blocks until all data is read, only to fail when the
 * stream is in error.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_read (int stream, uint8_t *buf, uint32_t len) {
	uint32_t sofar = 0;
	while (sofar < len) {
		ssize_t done = read (stream, &buf[sofar], len-sofar);
		if (done <= 0) {
			if (done == 0) {
				errno = ERANGE;
			}
			return false;
		}
		sofar += done;
	}
	if (sofar > len) {
		errno = ERANGE;
		return false;
	}
	return true;
}


/* Write a given number of bytes of data to the output stream.
 * This may block.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_write (int stream, uint8_t *buf, uint32_t len) {
	ssize_t done = write (stream, buf, len);
	if (done <= 0) {
		if (done == 0) {
			errno = EPIPE;
		}
		return false;
	} else if (done != len) {
		errno = ERANGE;
		return false;
	} else {
		return true;
	}
}


/* Write the given len_flags to downstream.
 * This may block.
 *
 * Being the first word in an individual exchange, this will
 * silently (re)open the stream if it was closed by the KDC.
 * The KDC is not supposed to close the stream at any later
 * time, but it may close it at any time after having sent
 * len_flags with optional data.  This routine compensates
 * for that.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_write_len_flags_down (int *downstream, uint32_t len_flags) {
	uint8_t buf4 [4];
	* (uint32_t *) &buf4[0] = htonl (len_flags);
	if (*downstream >= 0) {
		if (tcp_write (*downstream, buf4, 4)) {
			return true;
		}
	}
	*downstream = tcp_connect_kdc ();
	if (*downstream >= 0) {
		if (tcp_write (*downstream, buf4, 4)) {
			return true;
		}
	}
	return false;
}


/* Write the given len_flags to upstream.
 * This may block.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_write_len_flags_up (int upstream, uint32_t len_flags) {
	uint8_t buf4 [4];
	* (uint32_t *) &buf4[0] = htonl (len_flags);
	if (upstream >= 0) {
		if (tcp_write (upstream, buf4, 4)) {
			return true;
		}
	}
	return false;
}


/* Pass a given number of bytes of data from input stream to
 * output stream.  This may block.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_pass (int instream, int outstream, uint32_t len) {
	uint8_t buf [1500];
	bool ok = true;
	while (ok && (len > 0)) {
		int todo = (todo > sizeof (buf)) ? sizeof (buf) : todo;
		ok = ok && tcp_get (instream, buf, todo);
		ok = ok && tcp_put (instream, buf, todo);
		len -= todo;
	}
	return ok;
}


/* Read a length-or-flags value from the input stream.  Which
 * of the two is returned should be considered elsewhere.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_read_len_flags (int stream, uint32_t *len_flags) {
	uint8_t buf4 [4];
	bool ok;
	ok = tcp_read (stream, buf4, 4);
	if (ok) {
		*len_flags = ntohl (* (uint32_t *) buf4);
	}
	return ok;
}


/* Decide what handling method is appropriate, based on the
 * len_flags retrieved from a TCP connection.
 *
 * Treatment of the TCPFLAGS_KERBEROS return value may later
 * also turn out to be local, when it is a KX-OFFER coming
 * in from a client realm, or when the KDC returns an error
 * KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN to indicate that it could
 * not find the resolve service/host.name@SREALM locally.
 * The information to detect those conditions is not available
 * yet when this function is run on just the len_flags value.
 *
 * This function always returns a meaningful result.
 */
tcpflags_t tcp_classify_flags (uint32_t len_flags) {
	if (len_flags & 0x80000000) {
		if (len_flags == 0x80000000) {
			return TCPFLAGS_PROBE;
		} else if (len_flags & 0x00000001) {
			if (len_flags == 0x80000001) {
				return TCPFLAGS_STARTTLS;
			} else {
				return TCPFLAGS_ERROR;
			}
		} else {
			return TCPFLAGS_DOWNSTREAM;
		}
	} else {
		if (len_flags > MAXLEN_KERBEROS) {
			return TCPFLAGS_ERROR;
		} else {
			return TCPFLAGS_KERBEROS;
		}
	}
}


/* Having classified TCPFLAGS_PROBE from upstream, relay
 * that request and insert the STARTTLS option before
 * passing it back up.
 *
 * Two probes in sequel are considered a client request
 * for the KDC to close the connection; this is assumed
 * to be implemented in the downstream KDC.
 *
 * When the KDC does not understand the downstream probe,
 * it would return an error, detectable by a zero high bit
 * in the len_flags returned, which we should pass upstream.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_handle_probe (int upstream, int *downstream) {
	bool ok = true;
	uint32_t probe = 0;
	ok = ok && tcp_write_len_flags (downstream, probe);
	ok = ok && tcp_read_len_flags (*downstream, &probe);
	if ((probe & 0x80000000) == 0x00000000) {
		/* KDC did not understand it and will close the connection */
		close (*downstream);
		*downstream = -1;
		probe = 0x00000000;
	}
	/* Assure STARTTLS and pass the result back up */
	probe |= 0x00000001;
	ok = ok && tcp_write_len_flags_up (upstream, probe);
	return ok;
}


/* Having classified TCPFLAGS_STARTTLS from upstrean,
 * switch to TLS for the current connection.  This will
 * in general set a new file descriptor and close the
 * previous one.
 *
 * This is not in any way reflected in the downstream TCP
 * connection, which simply continues what it was doing.
 * The TLS connection is assumed to serve privacy from the
 * client to us, not from us to the KDC, and importantly,
 * to authenticate KXOVER exchanges as well as allow their
 * derivation of shared keys via RFC 5705.
 *
 * TODO: Return a TLS Pool handle for client inquiries.
 *
 * The protected_upstream parameter can safely point to
 * the same variable that provides the upstream parameter.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_handle_starttls (int upstream, int *protected_upstream) {
	*protected_upstream = -1;
	int withtls = tlspool_starttls (upstream);
	if (withtls < 0) {
		//TODO// Is errno always set?
		return false;
	}
	*protected_upstream = withtls;
	return true;
}


/* Having classified TCPFLAGS_KERBEROS from upstream,
 * interpret the read Kerberos data and see if it should be
 * handled locally, or passed to the downstream.
 *
 * This function always returns a meaningful result.
 * Possible return values are TCPKRB5_PASS, _KXOVER_REQ as
 * well as _ERROR.
 */
tcpkrb5_t tcp_classify_kerberos_down (uint8_t *krbptr, uint32_t krblen) {
	dercursor crs;
	crs.derptr = krbptr;
	crs.derlen = krblen;
	uint8_t tag;
	size_t intlen;
	uint8_t hdrlen;
	if (der_header (&crs, &tag, &intlen, &hdrlen) != 0) {
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


/* Having classified TCPKRB5_PASS from downstream,
 * interpret the read Kerberos data and see if it should be
 * handled locally, or passed to the downstream.
 *
 * This function always returns a meaningful result.
 * Possible return values are TCPKRB5_PASS, _NOTFOUND
 * and _KXOVER_REP as well as _ERROR.
 */
tcpkrb5_t tcp_classify_kerberos_up (uint8_t *krbptr, uint32_t krblen) {
	dercursor crs;
	crs.derptr = krbptr;
	crs.derlen = krblen;
	uint8_t tag;
	size_t intlen;
	uint8_t hdrlen;
	if (der_header (&crs, &tag, &intlen, &hdrlen) != 0) {
		return TCPKRB5_ERROR;
	}
	if (hdrlen + intlen != krblen) {
		return TCPKRB5_ERROR;
	}
	switch (tag) {
	case APPTAG_KRB_ERROR:
		if (der_walk (crs, krberror2code) != 0) {
			return TCPKRB5_ERROR;
		}
		if ((crs.derlen == sizeof (der_notfound)) &&
				(memcmp (der_notfound, crs.derptr, crs.derlen) == 0)) {
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


/* Having classified TCPKRB5_PASS from upstream, pass the
 * len_flags and Kerberos data down.  The response will not
 * be processed, as it will have to be classified and handled
 * separately.
 *
 * Return true on success, false on failure with errno set.
 */
bool tcp_handle_krbpass_down (int *downstream, uint32_t len_flags, uint8_t *krbptr, uint32_t krblen) {
	bool ok = true;
	ok = ok && tcp_write_len_flags (downstream, len_flags);
	ok = ok && tcp_write (*downstream, krbptr, krblen);
	return ok;
}


 * TODO :- TCPKRB5_PASS down2up:
 *
 * The response might be an error that gives rise to realm
 * crossover (KXOVER) with the current KDC as a client.
 * We block the current process to realise this.
 *
 * Success would also be reported when an error at the
 * Kerberos level is successfully passed to the upstream.
 *
 * When the downstream responds with something the classifies
 * as something else than TCPKRB5_PASS, it will be handled
 * internally with calls to appropriate service functions.


/* Having classified TCPKRB5_KXOVER_REQ from upstream,
 * handle it locally by validating the client and, if
 * acceptable, constructing a key for realm crossover
 * and passing back the response.
 */
TODO


/* Having classified TCPKRB5_KXOVER_REP from downstream,
 * handle it locally by finishing realm crossover and
 * continuing processing after it completes.
 */
TODO


/* Having classified TCPKRB5_NOTFOUND from downstream,
 * handle it locally by initiating realm crossover.
 */
TODO


