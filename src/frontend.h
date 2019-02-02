

/* The frontend structure collects information about requests
 * that arrived in the front end, to hold data while they are
 * being processed.
 */
typedef struct frontend {
	/* The socket for the front-end connection */
	int sox;
	/* The socket address of the requester (for UDP) */
	struct sockaddr remote;
	/* The data buffer to hold a current request */
	size_t buflen;
	uint8_t *bufptr;
	/* Whether the connection used TCP instead of UDP */
	bool uses_tcp;
	/* Whether a TCP connection switched to TLS */
	bool over_tls;
	/* Whether a TLS client identity was validated under DANE */
	bool dane_validated_clientid;
} frontend_t;


