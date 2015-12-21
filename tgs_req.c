#include "tgs_req.h"



int process_tgs_req( krb5_data pkt) {	//maybe you get a krb5_kdc_req instead of a krb5_data
	krb5_error_code retval;	
	krb5_kdc_req *request=0;
	krb5_context context;
	char *hostname = NULL;
	char cleanname[1024];
	char *query;
	int ret,i;
	int max = 5;
	char* array[max];
	int size = 0;
	char *realm;

	/*	Initiate context	*/
	retval = krb5_init_context(&context);
	if(retval) {
		com_err("kxover-deamon", retval, "while initiating context");
		return retval;
	}

	
	retval = decode_krb5_tgs_req(pkt, &request);
	if (retval) {
		com_err("kxover-deamon", retval, "while decoding request");
		return retval;

	}
	
	/*	Obtaine hostname	*/
	hostname = data2string(krb5_princ_component(context, request->server, 1));
	if (hostname == NULL) {
		return -1;
	}

	/* 	Clean hostname		*/
	retval = k5_clean_hostname(context, hostname, cleanname, sizeof(cleanname));
	if (retval) {
		com_err("kxover-deamon", retval, "while cleaning hostname");
		return retval;
	}
	
	/*	Issue TXT record query		*/
	/*	-> add _kerberos to the hostname */
	if((query = malloc(strlen(cleanname) + strlen("_kerberos.")+1)) != NULL) {
		query[0] = '\0';
		strcat(query, "_kerberos.");
		strcat(query, cleanname);
	} else {
		com_err("kxover-deamon", retval, "while allocating memory");
		return -1;
	}
	/*	-> call lookup function		*/
	ret = lookupTXT(query, max, array, &size);
	for(i = 0; i < size; i++) {
		//choose the appropiate realm name
		realm = array[i];
	}
	
	/*	Issue SRV record query		*/
	return 0;

}
