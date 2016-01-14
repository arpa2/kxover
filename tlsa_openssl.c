#include "tlsa_openssl.h"



int verify_certificate(getdns_list * tlsas, size_t ntlsas, X509 *cert) {
	int i, ret, result= -1;
	getdns_dict * tlsa_rr;
	getdns_dict * rdata;
	uint32_t usage, selector, matching_type;
	getdns_bindata * data;
	unsigned char *buf = NULL;
	size_t len;
	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA512_CTX sha512;


	for(i = 0; i < ntlsas; i++) {
		result = 0;
		ret = getdns_list_get_dict(tlsas, i, &tlsa_rr);
	
		ret = getdns_dict_get_dict(tlsa_rr, "rdata", &rdata);

		ret = getdns_dict_get_int(rdata, "certificate_usage", &usage);

		ret = getdns_dict_get_int(rdata, "selector", &selector);
		
		ret = getdns_dict_get_int(rdata, "matching_type", &matching_type);

		ret = getdns_dict_get_bindata(rdata, "certificate_association_data", &data);
		
		if(usage != 3 || selector != 0 || matching_type > 2) {
			result = -1;
			break;
		}	
		/*	check the cert		*/	
		len = (size_t)i2d_X509(cert, &buf);

		switch(matching_type) {
		case 0:
			if(data->size != len || memcmp(data->data, buf, len))
				result = -1;
			break;

		case 1:
			if(data->size != SHA256_DIGEST_LENGTH)
				result = -1;
			else {
				SHA256_Init(&sha256);
				SHA256_Update(&sha256, buf, len);
				SHA256_Final(hash, &sha256);
				if(memcmp(data->data, hash, SHA256_DIGEST_LENGTH))
					result = -1;
			}	
			break;

		case 2:
			if(data->size != SHA512_DIGEST_LENGTH)
				result = -1;
			else {
				SHA512_Init(&sha512);
				SHA512_Update(&sha512, buf, len);
				SHA512_Final(hash, &sha512);
				if(memcmp(data->data, hash, SHA512_DIGEST_LENGTH))
					result = -1;
			}	
			break;
			
		default:
			result = -1;
		}	
		if(result == 0)
			return 0;
	}	
	return result;
}
	
int checkTLSA(getdns_list * tlsas, char* target, int port) {
	int ntlsas;
	int ret, i, ssl_status;
	getdns_list * addresses;
	int naddresses;

	SSL_CTX *ctx;
	X509 *cert;
	SSL *ssl;


	ret = getdns_list_get_length(tlsas, (size_t *)&ntlsas);

	printf("tlsa record found. Size: %d\n",ntlsas);

	/*	Check TLSA record		*/
	/*	->lookup IP address		*/
	
	addresses = getdns_list_create();
	
	ret = lookupIP(target, addresses);	
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while issuing address lookup");
		return ret;
	}
	ret = getdns_list_get_length(addresses, (size_t *)&naddresses);
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while getting length of the addresses");
		return ret;
	}

	/*	->Initialize OpenSSL	*/	
	


	SSL_load_error_strings();
	SSL_library_init();

	ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx) {
		com_err("kxover-deamon", -1, "while creating SSL context");
		return -1;
	}	

	/*	->for each address connect and verify	*/
	int checked = -1;
	for(i = 0; i < naddresses; i++) {
		getdns_dict * address;
		getdns_bindata * address_type;
		getdns_bindata * address_data;
		struct sockaddr_storage sas;
		struct sockaddr_in *sa4 = (struct sockaddr_in *)&sas;
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sas;
		size_t sa_len;
		int sock;
		

		ret = getdns_list_get_dict(addresses, i, &address);
		if(ret != 0) {
			com_err("kxover-deamon", ret, "while getting address");
			continue;
		}


		ret = getdns_dict_get_bindata(address, "address_type", &address_type);
		if(ret != 0) {
			com_err("kxover-deamon", ret, "while getting address type");
			continue;
		}
		ret = getdns_dict_get_bindata(address, "address_data", &address_data);
		if(ret != 0) {
			com_err("kxover-deamon", ret, "while getting address data");
			continue;
		}

		if(0 == strncmp((const char *) address_type->data, "IPv4", 4)) {
			sas.ss_family = AF_INET;
			sa4->sin_port = htons(port);
			memcpy(&(sa4->sin_addr), address_data->data, address_data->size < 4 ? address_data->size : 4);
			sa_len = sizeof(struct sockaddr_in);
		}
		else if(0 == strncmp((const char *) address_type->data, "IPv6", 4)) {
			sas.ss_family = AF_INET6;
			sa6->sin6_port = htons(port);
			memcpy(&(sa6->sin6_addr), address_data->data, address_data->size < 4 ? address_data->size : 4);
			sa_len = sizeof(struct sockaddr_in6);
		}
		else {
			com_err("kxover-deamon", -1, "unknown address type");
			continue;
		}
		
		char *buf = getdns_display_ip_address(address_data);
		printf("connecting to: %s\n", buf);


		/*	--> open and tcp-connect a socket	*/
		sock = socket(sas.ss_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock == -1) {
			com_err("kxover-deamon", -1, "while creating socket");
			continue;
		}
		
		if (connect(sock, (struct sockaddr *)&sas, sa_len) ==-1) {
			com_err("kxover-deamon", -1, "while connecting socket");
			close(sock);
			continue;
		}	

		ssl = SSL_new(ctx);
		if(! ssl) {
			com_err("kxover-deamon", -1, "while setting up ssl");
			close(sock);
			continue;
		}
		
		(void) SSL_set_tlsext_host_name(ssl, target);

		SSL_set_connect_state(ssl);
		(void) SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		if (! SSL_set_fd(ssl, sock)) {
			com_err("kxover-deamon", -1, "while setting up ssl");
			SSL_free(ssl);
			close(sock);
			continue;
		}

		for(;;) {
			if ((ssl_status = SSL_do_handshake(ssl)) == 1) {
				break;
			}
			ssl_status = SSL_get_error(ssl, ssl_status);
			if (ssl_status != SSL_ERROR_WANT_READ && ssl_status != SSL_ERROR_WANT_WRITE) {
				ret = GETDNS_RETURN_GENERIC_ERROR;
				break;
			}
		}
		if(ret == GETDNS_RETURN_GENERIC_ERROR) {
			com_err("kxover-deamon", -1, "while handshaking");
			SSL_free(ssl);
			close(sock);
			continue;
		}
		
		cert = SSL_get_peer_certificate(ssl);

		puts("i got the certificate from the peer");
		/*	->check the certificate against the tlsa one	*/
		ret = verify_certificate(tlsas, ntlsas, cert);
		if( ret == 0) {
			checked = 0;
			puts("certificate verified");
			break;
		}
	}
	if(checked == -1) {
		com_err("kxover-deamon", -1, "no tlsa certificate was verified");
		return -1;
	}
	return 0;

}

