#include "as_rep.h"


int process_as_rep( krb5_data pkt) {
	krb5_error_code retval;
	krb5_context context;
	int ret;
	char * nonce;
	char * realm;
	char * remote_pub_key;
	struct request_list * request = NULL;
	char * secret;
	int len;
	char * princ_name;
	char * req_nonce;
	char * own_realm;


	retval = krb5_init_context(&context);
	if(retval) {
		com_err("kxover-deamon", retval, "while initiating context");
		return retval;
	}

	
	retval = krb5_get_default_realm(context, &own_realm);
	if (retval) {
		com_err("kxover-deamon", retval, "while getting default realm");
		return retval;
	}

	realm = (char *)malloc(200);
	remote_pub_key = (char *)malloc(66);
	nonce = (char *)malloc(32);

	ret = check_reply(pkt.data, pkt.length,realm, nonce, remote_pub_key);
	if( ret != 0) {
		puts("error while decoding AS_REP");
		return -1;
	}

	request = search(realm, NULL);
	if(request == NULL) {
		puts("related requeset not found");
		return -1;
	}

	req_nonce = request->nonce;

	if(strcmp(req_nonce, nonce) != 0) {
		puts("nonce missmatch");
		return -1;
	}

	/*	Generate shared secret		*/
	secret = malloc(65);
	ret = generateSecret(remote_pub_key, request->key, secret, &len);
	if(ret != 0) {
		puts("error while generating shared secret");
		return -1;
	}

	/*	Create principal in the DB 	*/

	if((princ_name = malloc(strlen("krbtgt/@")+strlen(realm)+strlen(own_realm)+1)) != NULL) {
		princ_name[0] = '\0';
		strcat(princ_name, "krbtgt/");
		strcat(princ_name, realm);
		strcat(princ_name, "@");
		strcat(princ_name, own_realm);
	} else {
		com_err("kxover-deamon", -1, "while allocating memory");
		return -1;
	}
	ret = create_princ(princ_name, secret);
	if(ret != 0) {
		com_err("kxover-deamon", -1, "while creating principal");
		return -1;	
	}

	/*	Delete the request from the request list	*/
	ret = delete_from_list(realm);
	if( ret != 0) {
		puts("error while deleting request from the list");
		return -1;
	}

	puts("Reply Processed, principal added to the DB");

	return 0;

}
