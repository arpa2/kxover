#include "tgs_req.h"



int process_tgs_req( krb5_data pkt) {	//maybe you get a krb5_kdc_req instead of a krb5_data
	krb5_error_code retval;	
	krb5_kdc_req *request=0;
	krb5_context context;
	char *hostname = NULL;
	char *query;
	int ret, i, ssl_status;
	int max = 5;
	char* array[max];
	int size = 0;
	char *realm;
	char *target;
	int port = 0;
	getdns_bindata * tlsacert;

	/*	Initiate context	*/
	retval = krb5_init_context(&context);
	if(retval) {
		com_err("kxover-deamon", retval, "while initiating context");
		return retval;
	}

	
	retval = decode_krb5_tgs_req(&pkt, &request);
	if (retval) {
		com_err("kxover-deamon", retval, "while decoding request");
		return retval;
	}
	
	/*	Obtain hostname	*/
	hostname = data2string(krb5_princ_component(context, request->server, 1));
	if (hostname == NULL) {
		return -1;
	}

	
	/*	Issue TXT record query		*/
	/*	-> add _kerberos to the hostname */
	if((query = malloc(strlen(hostname) + strlen("_kerberos.")+1)) != NULL) {
		query[0] = '\0';
		strcat(query, "_kerberos.");
		strcat(query, hostname);
	} else {
		com_err("kxover-deamon", retval, "while allocating memory");
		return -1;
	}
	/*	-> call lookup function		*/
	ret = lookupTXT(query, max, array, &size);
	if(ret != 0) {
		com_err("kxover-deamon", retval, "while issuing TXT lookup");
		return retval;
	}
	//	-> choose the appropiate realm name
	realm = array[0];
	realm = realm + 2;
	realm[strlen(realm)-2] = 0;
	printf("Realm found: %s\n",realm);
	
	/*	Issue SRV record query		*/
	/*	-> compose query		*/
	if((query = malloc(strlen(hostname) + strlen("_kerberos._udp.")+1)) != NULL) {
		query[0] = '\0';
		strcat(query, "_kerberos._udp.");
		strcat(query, hostname);
	} else {
		com_err("kxover-deamon", retval, "while allocating memory");
		return -1;
	}
	/*	-> call lookup function		*/
	target = (char *)malloc(255*sizeof(char));
	ret = lookupSRV(query, target, &port);
	if(ret != 0) {
		com_err("kxover-deamon", retval, "while issuing SRV lookup");
		return retval;
	}
	printf("target found: %s\n", target);
	printf("port found: %d\n", port);

	/*	Issue TLSA record query		*/
	/*	-> compose query		*/
	char port_string[5];
	sprintf(port_string, "%d", port); 
	if((query = malloc(strlen(realm) + strlen("_._udp.")+strlen(port_string)+1)) != NULL) {
		query[0] = '\0';
		strcat(query, "_");
		strcat(query, port_string);
		strcat(query, "._udp.");
		strcat(query, realm);
		printf("query: %s\n", query);
	} else {
		com_err("kxover-deamon", -1, "while allocating memory");
		return -1;
	}
	/*	-> call the lookup function	*/
	tlsacert = (struct getdns_bindata *) malloc(sizeof(struct getdns_bindata));
	ret = lookupTLSA(query, tlsacert);
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while issuing TLSA lookup");
		return ret;
	}
	printf("tlsa record found. Size: %zu\n", tlsacert->size);

	/*	Check TLSA record		*/
	/*	->lookup IP address		*/
	getdns_list * addresses;
	addresses = getdns_list_create();
	int naddresses;
	ret = lookupIP(target, addresses);	
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while issuing address lookup");
		return retval;
	}
	ret = getdns_list_get_length(addresses, (size_t *)&naddresses);
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while getting length of the addresses");
		return ret;
	}

	/*	->Initialize OpenSSL	*/	
	SSL_CTX *ctx;
	X509 *cert;
	SSL *ssl;
	STACK_OF(X509) *extra_certs;


	SSL_load_error_strings();
	SSL_library_init();

	ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx) {
		com_err("kxover-deamon", -1, "while creating SSL context");
		return -1;
	}	

	/*	->for each address connect and verify	*/
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
			break;
		}


		ret = getdns_dict_get_bindata(address, "address_type", &address_type);
		if(ret != 0) {
			com_err("kxover-deamon", ret, "while getting address type");
			break;
		}
		ret = getdns_dict_get_bindata(address, "address_data", &address_data);
		if(ret != 0) {
			com_err("kxover-deamon", ret, "while getting address data");
			break;
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
			break;
		}
		
		char *buf = getdns_display_ip_address(address_data);
		printf("connecting to: %s\n", buf);


		/*	--> open and tcp-connect a socket	*/
		sock = socket(sas.ss_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock == -1) {
			com_err("kxover-deamon", -1, "while creating socket");
			break;
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
		extra_certs = SSL_get_peer_cert_chain(ssl);

		puts("i got the certificate from the peer");
		/*	->check the certificate against the tlsa one	*/

	}

	return 0;

}
