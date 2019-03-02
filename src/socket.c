/* Socket utilities, including parsing and sockaddr juggling.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include "socket.h"

#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>


/* Given a socket address, determine its length.
 *
 * This function does not fail.
 *
 * TODO:inline
 */
socklen_t sockaddrlen (const struct sockaddr *sa) {
	assert ((sa->sa_family == AF_INET6) || (sa->sa_family == AF_INET));
	if (sa->sa_family == AF_INET6) {
		return sizeof (struct sockaddr_in6);
	} else {
		return sizeof (struct sockaddr_in );
	}
}


/* Parse an address and port, and store them in a sockaddr of
 * type AF_INET or AF_INET6.  The space provided is large enough
 * to hold either, as it is defined as a union.
 *
 * The opt_port may be NULL, in which case the port is set to 0
 * in the returned sockaddr; otherwise, its value is rejected
 * if it is 0.
 *
 * We always try IPv6 address parsing first, but fallback to
 * IPv4 if we have to, but that fallback is deprecated.  The
 * port will be syntax-checked and range-checked.
 *
 * Return true on success, or false with errno set on error.
 */
bool socket_parse (char *addr, char *opt_port, struct sockaddr *out_sa) {
	//
	// Optional port parsing
	uint16_t portnr = 0;
	if (opt_port != NULL) {
		long p = strtol (opt_port, &opt_port, 10);
		if (*opt_port != '\0') {
			errno = EINVAL;
			return false;
		}
		if ((p == LONG_MIN) || (p == LONG_MAX) || (p <= 0) || (p > 65535)) {
			/* errno is ERANGE */
			return false;
		}
	}
	//
	// IPv6 address parsing
	struct af_ofs { int af; int aofs; int pofs; };
	static const struct af_ofs aofs [3] = {
		{ AF_INET6, offsetof (struct sockaddr_in6, sin6_addr),
		            offsetof (struct sockaddr_in6, sin6_port) },
		{ AF_INET,  offsetof (struct sockaddr_in,  sin_addr ),
		            offsetof (struct sockaddr_in,  sin_port ) },
	        { -1, -1, -1 }
	};
	const struct af_ofs *aofsp = &aofs [0];
	for (aofsp = &aofs [0]; aofsp->aofs != -1; aofsp++) {
		memset (out_sa, 0, sizeof (struct sockaddr));
		switch (inet_pton (aofsp->af, addr, (((uint8_t *) out_sa) + aofsp->aofs))) {
		case 1:
			out_sa->sa_family = aofsp->af;
			* (uint16_t *) (((uint8_t *) out_sa)
					+ aofsp->pofs) = htons (portnr);
			return true;
		case 0:
			/* Invalid address did not set errno */
			errno = EINVAL;
			continue;
		default:
			continue;
		}
	}
	//
	// Report the last error; this is usually EINVAL
	errno = EINVAL;
	return false;
}


/* Open a connection as a client, to the given address.  Do not bind locally.
 *
 * Set contype to one SOCK_DGRAM, SOCK_STREAM or SOCK_SEQPACKET.
 *
 * The resulting socket is written to out_sox.
 *
 * Return true on success, or false with errno set on failure.
 * On error, *out_sox is set to -1.
 */
bool socket_client (const struct sockaddr *peer, int contype, int *out_sox) {
	int sox = -1;
       	sox = socket (peer->sa_family, contype, 0);
	if (sox < 0) {
		goto fail;
	}
	if (connect (sox, peer, sockaddrlen (peer)) != 0) {
		goto fail;
	}
	int soxflags = fcntl (sox, F_GETFL, 0);
	if (fcntl (sox, F_SETFL, soxflags | O_NONBLOCK) != 0) {
		goto fail;
	}
	*out_sox = sox;
	return true;
fail:
	*out_sox = -1;
	if (sox >= 0) {
		close (sox);
	}
	return false;
}


/* Open a listening socket as a server, at the given address.
 *
 * Set contype to one of SOCK_DGRAM, SOCK_STREAM or SOCK_SEQPACKET.
 *
 * The resulting socket is written to out_sox.
 *
 * Return true on success, or false with errno set on failure.
 * On error, *out_sox is set to -1.
 */
bool socket_server (const struct sockaddr *mine, int contype, int *out_sox) {
	int sox = -1;
       	sox = socket (mine->sa_family, contype, 0);
	if (sox < 0) {
		goto fail;
	}
	if (bind (sox, mine, sockaddrlen (mine)) != 0) {
		goto fail;
	}
	if ((contype == SOCK_STREAM) || (contype == SOCK_SEQPACKET)) {
		if (listen (sox, 10) != 0) {
			goto fail;
		}
	}
	int soxflags = fcntl (sox, F_GETFL, 0);
	if (fcntl (sox, F_SETFL, soxflags | O_NONBLOCK) != 0) {
		goto fail;
	}
	*out_sox = sox;
	return true;
fail:
	*out_sox = -1;
	if (sox >= 0) {
		close (sox);
	}
	return false;
}


