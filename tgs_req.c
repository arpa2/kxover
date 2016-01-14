#include "tgs_req.h"



int process_tgs_req( krb5_data pkt) {	//maybe you get a krb5_kdc_req instead of a krb5_data
	krb5_error_code retval;	
	krb5_kdc_req *request=0;
	krb5_context context;
	char *hostname = NULL;
	char *query;
	int ret;
	int max = 5;
	char* array[max];
	int size = 0;
	char *realm;
	char *target;
	int port = 0;

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
	getdns_list * tlsas;
	tlsas = getdns_list_create();
	ret = lookupTLSA(query, tlsas);
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while issuing TLSA lookup");
		return ret;
	}
	
	/*	Check TLSA record	*/
	ret = checkTLSA(tlsas, target, port);
	if(ret != 0) {
		com_err("kxover-deamon", ret, "while checking TLSA");
		return ret;
	}

	/*	Start PKINIT		*/
	

	return 0;

}

