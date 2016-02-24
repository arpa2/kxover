#include "as_req.h"



int process_as_req( krb5_data pkt) {	//maybe you get a krb5_kdc_req instead of a krb5_data
	krb5_error_code retval;	
	krb5_kdc_req *request=0;
	krb5_context context;
	char *query;
	int ret;
	char *realm;
	char *target;
	int port = 0;
	char *cname;
	char *sname;
	char * own_realm;
	char * as_rep;
	int as_rep_size = 0;

	/*	Initiate context	*/
	retval = krb5_init_context(&context);
	if(retval) {
		com_err("kxover-deamon", retval, "while initiating context");
		return retval;
	}

	
	retval = decode_krb5_as_req(&pkt, &request);
	if (retval) {
		com_err("kxover-deamon", retval, "while decoding request");
		return retval;
	}

	retval = krb5_get_default_realm(context, &own_realm);
	if (retval) {
		com_err("kxover-deamon", retval, "while getting default realm");
		return retval;
	}
		
	
	/*	Obtain client realm 	*/
	cname = data2string(krb5_princ_name(context, request->client));
	if (cname == NULL) {
		return -1;
	}
	//	kxover@ -> 7 chars
	realm = (char *) malloc(strlen(cname)-6);
	strncpy(realm, cname+7, strlen(cname)-7);	
	strcat(realm, "\0");

	printf("client name: %s\n" , cname);
	printf("realm: %s\n", realm);
	
	/*	Issue SRV record query		*/
	/*	-> compose query		*/
	if((query = malloc(strlen(realm) + strlen("_kerberos._udp.")+1)) != NULL) {
		query[0] = '\0';
		strcat(query, "_kerberos._udp.");
		strcat(query, realm);
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
	getdns_list * tlsas;
	tlsas = getdns_list_create();
	ret = lookupTLSA(query, tlsas);
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while issuing TLSA lookup");
		return ret;
	}
	
	/*	Check TLSA record	*/
	/*ret = checkTLSA(tlsas, target, port);
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while checking TLSA");
		return ret;
	}
*/
	/*	Obtain ECDH parameters		*/
	printf("message received, size: %d\n", pkt.length);
	
	char * remote_pub_key;
	krb5_pa_data ** padata;
	remote_pub_key = (char *)malloc(66);
        for(padata = request->padata; *padata; padata++) {
		krb5_data kxover_data;
		kxover_data.length = (*padata)->length;
		kxover_data.data = (char *)(*padata)->contents;
		if((*padata)->pa_type == 16) {
			ret = check_certificate(pkt.data, pkt.length, remote_pub_key);
			if(ret < 0) puts("error on check");
		}
        }
	/*	Create key pair		*/
	EC_KEY * key;
	key = generateKeys();
	if(key == NULL) {
		puts("error while generating key pair");
		return -1;
	}


	/*	Create ECDH shared secret	*/
	char * secret;
	int len;
	secret = malloc(65);
	ret = generateSecret(remote_pub_key, key, secret, &len); 
	if(ret != 0) {
		printf("error when generating shared secret, %d\n", ret);
		return -1;
	}

	hexdump(secret, len);

	printf("Shared secret: %s\n", secret);

	/*	Create principal in the DB	*/

	/*	Generate AS-REP		*/
	/*if((sname = malloc(strlen("kxover@")+strlen(realm)+1)) != NULL) {
		sname[0] = '\0';
		strcat(sname, "kxover@");
		strcat(sname, realm);
	} else {
		com_err("kxover-deamon", -1, "while allocating memory");
		return -1;
	}
	if((cname = malloc(strlen("kxover@")+strlen(own_realm)+1)) != NULL) {
		cname[0] = '\0';
		strcat(cname, "kxover@");
		strcat(cname, own_realm);
	} else {
		com_err("kxover-deamon", -1, "while allocating memory");
		return -1;
	}
	
	as_rep = (char *)malloc(1024*sizeof(char));
	ret = create_as_rep(cname, sname, realm, as_rep, &as_rep_size);
	if(ret != 0) {
		com_err("kxover-deamon", -1, "while creating AS-REQ");
		return -1;
	}
	printf("AS-REQ created, size: %d\n",as_rep_size);
	*/
	/*	Send AS-REP	*/
	int fd;
	/*	-> Connect to the remote KDC	*/
/*	struct addrinfo hints, *res;
	struct in_addr addr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	
	if(( ret = getaddrinfo(target, NULL, &hints, &res)) != 0) {
		printf("error while getting address: %d\n", ret);
		return -1;
	}
	addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;


	struct sockaddr_in server;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd == -1) {
		puts("error creating socket");
		return -1;
	}
	
	server.sin_addr = addr;
	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	
	if(connect(fd, (struct sockaddr *)&server, sizeof(server))<0) {
		puts("error when connecting");
		return -1;
	}
	
	uint32_t nl_as_rep_size = htonl(as_rep_size);

	if(send(fd, &nl_as_rep_size, sizeof(nl_as_rep_size), 0) < 0) {
		puts("error when sending length");
		return -1;
	}

	if(send(fd, as_rep, as_rep_size, 0) < 0) {
		puts("error when sending");
		return -1;
	}
*/	puts("message sent");

	free(realm);
	free(query);
	free(target);
	free(remote_pub_key);
	return 0;

}
