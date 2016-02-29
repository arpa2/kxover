#include "asn1.h"


int check_reply(char * data, int size, char * realm, char *nonce, char * public_key) {
	ASN1_TYPE def=ASN1_TYPE_EMPTY;	
	asn1_node message;
	asn1_node pa_pk_as_rep;
	asn1_node contentInfo;
	asn1_node signedData;
	asn1_node keyInfo;
	unsigned char der_data[size];
	asn1_retCode ret;
	char * error = NULL;
	char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	int len = 0;
	char * aux;

	void * der_padata;
	void * dhSignedData;
	void * der_signedData;
	void * der_KDCDHKeyInfo;
	void * pubKey;
	
	
	memcpy(der_data, data, size);
	
	ret = asn1_array2tree(kerberosV5spec2_asn1_tab, &def, error);
	if(ret) {
		printf("error: %s\n", error);
		return -1;
	}

	ret = asn1_create_element(def, "KerberosV5Spec2.AS-REP", &message);
	if(ret) {
		printf("error while creating pa-data, %d\n", ret);
		return -1;
	}

	ret = asn1_der_decoding(&message, der_data, size, errorDescription); 
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding message, %s, %d\n", errorDescription, ret);
		return -1;
	}

	/*	Get realm	*/
	ret = asn1_read_value(message, "crealm", NULL, &len);
	if(ret != ASN1_MEM_ERROR) {
		printf("error while reading realm, %d\n", ret);
		return -1;
	}
	aux = malloc(len);
	ret = asn1_read_value(message, "crealm", aux, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading realm, %d\n", ret);
		return -1;
	}

	strcpy(realm, aux);

	/*	Get Padata	*/
	//	-> get der-encoded data
	len = 0;
	ret = asn1_read_value(message, "padata.?2.padata-value", NULL, &len);
	if(ret != ASN1_MEM_ERROR){
		printf("error while reading padata value, %d\n", ret);
		return -1;
	}
	der_padata = malloc(len);
	ret = asn1_read_value(message, "padata.?2.padata-value", der_padata, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading padata value, %d\n", ret);
		return -1;
	}


	//	-> decode into PA-PK-AS-REP
	ret = asn1_create_element(def, "KerberosV5Spec2.PA-PK-AS-REP", &pa_pk_as_rep);
	if(ret != ASN1_SUCCESS) {
		printf("error while creating element, %d\n", ret);
		return -1;
	}

	

	ret = asn1_der_decoding(&pa_pk_as_rep, der_padata, len, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding pa-pk-as-rep, %s, %d\n", errorDescription, ret);
		return -1;
	}

	
	len = 0;
	ret = asn1_read_value(pa_pk_as_rep, "dhInfo.dhSignedData", NULL, &len);
	if(ret != ASN1_MEM_ERROR){
		printf("error while reading dhSignedData, %d\n", ret);
		return -1;
	}
	dhSignedData = malloc(len);
	ret = asn1_read_value(pa_pk_as_rep, "dhInfo.dhSignedData", dhSignedData, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading dhSignedData, %d\n", ret);
		return -1;
	}

	//	dhSignedData is a der-encoded ContentInfo


	ret = asn1_create_element(def, "KerberosV5Spec2.ContentInfo", &contentInfo);
	if(ret != ASN1_SUCCESS) {
		printf("error while creating contentInfo, %d\n", ret);
		return -1;
	}

	ret = asn1_der_decoding(&contentInfo, dhSignedData, len, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding contentInfo, %s, %d\n", errorDescription, ret);
		return -1;
	}

	
	len = 0;
	ret = asn1_read_value(contentInfo, "content", NULL, &len);
	if(ret != ASN1_MEM_ERROR) {
		printf("error while reading signedData, %d\n", ret);
		return -1;
	}
	der_signedData = malloc(len);
	ret = asn1_read_value(contentInfo, "content", der_signedData, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading signedData, %d\n", ret);
		return -1;
	}


	//	SignedData is der-encoded instead of signed (SHOULD BE CHANGED)

	ret = asn1_create_element(def, "KerberosV5Spec2.SignedData", &signedData);
	if(ret != ASN1_SUCCESS) {
		printf("error while creating SignedData, %d\n", ret);
		return -1;
	}

	ret = asn1_der_decoding(&signedData, der_signedData, len, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding SignedData, %s, %d\n", errorDescription, ret);
		return -1;
	}
	

	len = 0;
	ret = asn1_read_value(signedData, "encapContentInfo.eContent", NULL, &len);
	if(ret != ASN1_MEM_ERROR) {
		printf("error while reading eContent, %d\n", ret);
		return -1;
	}
	der_KDCDHKeyInfo = malloc(len);
	ret = asn1_read_value(signedData, "encapContentInfo.eContent", der_KDCDHKeyInfo, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading eContent, %d\n", ret);
		return -1;
	}


	ret = asn1_create_element(def, "KerberosV5Spec2.KDCDHKeyInfo", &keyInfo);
	if(ret != ASN1_SUCCESS) {
		printf("error while creating authPack, %d\n", ret);
		return -1;
	}

	

	ret = asn1_der_decoding(&keyInfo, der_KDCDHKeyInfo, len, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding authPack, %s, %d\n", errorDescription, ret);
		return -1;
	}

	asn1_print_structure(stdout, keyInfo, "", ASN1_PRINT_ALL);

	/*	Get Nonce		*/

 	uint8_t noncint[5];
        int nonclen = sizeof(noncint);

        ret = asn1_read_value(keyInfo, "nonce", noncint, &nonclen);
        if(ret != ASN1_SUCCESS) {
                printf("error while reading nonce, %d\n", ret);
                return -1;
        }

        char * hexout;
        hexout = malloc(32);
        sprintf(hexout, "%02x%02x%02x%02x", noncint[0],noncint[1],noncint[2],noncint[3]);


        long int n;
        n = strtol(hexout, NULL, 16);

        char nonce_char[32];
        sprintf(nonce_char, "%d", n);


        strcpy(nonce, nonce_char);

	
	/*	Get Public Key	*/
	len = 0;
	ret = asn1_read_value(keyInfo, "subjectPublicKey", NULL, &len);
	if(ret != ASN1_MEM_ERROR) {
		printf("error while reading public key, %d\n", ret);
		return -1;
	}
	pubKey = malloc(len/8);
	ret = asn1_read_value(keyInfo, "subjectPublicKey", pubKey, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading public key, %d\n", ret);
		return -1;
	}

	memcpy(public_key, pubKey, len/8);

	free(der_padata);
	free(der_signedData);
	free(signedData);
	free(pubKey);

	return 0;
}


int extract_public_key(char * data, int size, char * ecdh_public_key, char * nonce) {	// data contains AS-REQ
	ASN1_TYPE def=ASN1_TYPE_EMPTY;	
	asn1_node message;
	asn1_node pa_pk_as_req;
	asn1_node authPack;
	asn1_node contentInfo;
	asn1_node signedData;
	asn1_retCode ret;
	char * error = NULL;
	char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	unsigned char der_data[size];

	void * der_padata = NULL;
	int len = 0;
	void * signedAuthPack = NULL;
	void * der_signedData = NULL;
	void * der_authPack = NULL;
	void * pubKey = NULL;
	void * aux = NULL;

	memcpy(der_data, data, size);
	
	ret = asn1_array2tree(kerberosV5spec2_asn1_tab, &def, error);
	if(ret) {
		printf("error: %s\n", error);
		return -1;
	}

	ret = asn1_create_element(def, "KerberosV5Spec2.AS-REQ", &message);
	if(ret) {
		printf("error while creating pa-data, %d\n", ret);
		return -1;
	}

	ret = asn1_der_decoding(&message, der_data, size, errorDescription); 
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding message, %s, %d\n", errorDescription, ret);
		return -1;
	}

	//	Get nonce
	ret = asn1_read_value(message, "req-body.nonce", NULL, &len);
	if(ret != ASN1_MEM_ERROR) {
		printf("error while reading nonce, %d\n", ret);
		return -1;
	}
	aux = malloc(len);
	ret = asn1_read_value(message, "req-body.nonce", aux, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading nonce, %d\n", ret);
		return -1;
	}
	//convert hex to decimal before copying
	printf("nonce: %s\n", aux);
	hexdump(aux, len);

	memcpy(nonce, aux, len);

	asn1_print_structure(stdout, message, "", ASN1_PRINT_ALL);
	
	//	Get PA-DATA
	//	-> get der-encoded data
	len = 0;
	ret = asn1_read_value(message, "padata.?2.padata-value", NULL, &len);
	if(ret != ASN1_MEM_ERROR){
		printf("error while reading padata value, %d\n", ret);
		return -1;
	}
	der_padata = malloc(len);
	ret = asn1_read_value(message, "padata.?2.padata-value", der_padata, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading padata value, %d\n", ret);
		return -1;
	}


	//	-> decode into PA-PK-AS-REQ
	ret = asn1_create_element(def, "KerberosV5Spec2.PA-PK-AS-REQ", &pa_pk_as_req);
	if(ret != ASN1_SUCCESS) {
		printf("error while creating element, %d\n", ret);
		return -1;
	}

	

	ret = asn1_der_decoding(&pa_pk_as_req, der_padata, len, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding pa-pk-as-req, %s, %d\n", errorDescription, ret);
		return -1;
	}



	len = 0;
	ret = asn1_read_value(pa_pk_as_req, "signedAuthPack", NULL, &len);
	if(ret != ASN1_MEM_ERROR){
		printf("error while reading signedAuthPack, %d\n", ret);
		return -1;
	}
	signedAuthPack = malloc(len);
	ret = asn1_read_value(pa_pk_as_req, "signedAuthPack", signedAuthPack, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading signedAuthPack, %d\n", ret);
		return -1;
	}
	//	signedAuthPack is a der-encoded ContentInfo


	ret = asn1_create_element(def, "KerberosV5Spec2.ContentInfo", &contentInfo);
	if(ret != ASN1_SUCCESS) {
		printf("error while creating contentInfo, %d\n", ret);
		return -1;
	}

	ret = asn1_der_decoding(&contentInfo, signedAuthPack, len, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding contentInfo, %s, %d\n", errorDescription, ret);
		return -1;
	}

	
	len = 0;
	ret = asn1_read_value(contentInfo, "content", NULL, &len);
	if(ret != ASN1_MEM_ERROR) {
		printf("error while reading signedData, %d\n", ret);
		return -1;
	}
	der_signedData = malloc(len);
	ret = asn1_read_value(contentInfo, "content", der_signedData, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading signedData, %d\n", ret);
		return -1;
	}


	//	SignedData is der-encoded instead of signed (SHOULD BE CHANGED)

	ret = asn1_create_element(def, "KerberosV5Spec2.SignedData", &signedData);
	if(ret != ASN1_SUCCESS) {
		printf("error while creating SignedData, %d\n", ret);
		return -1;
	}

	ret = asn1_der_decoding(&signedData, der_signedData, len, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding SignedData, %s, %d\n", errorDescription, ret);
		return -1;
	}
	

	len = 0;
	ret = asn1_read_value(signedData, "encapContentInfo.eContent", NULL, &len);
	if(ret != ASN1_MEM_ERROR) {
		printf("error while reading eContent, %d\n", ret);
		return -1;
	}
	der_authPack = malloc(len);
	ret = asn1_read_value(signedData, "encapContentInfo.eContent", der_authPack, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error while reading eContent, %d\n", ret);
		return -1;
	}


	ret = asn1_create_element(def, "KerberosV5Spec2.AuthPack", &authPack);
	if(ret != ASN1_SUCCESS) {
		printf("error while creating authPack, %d\n", ret);
		return -1;
	}

	

	ret = asn1_der_decoding(&authPack, der_authPack, len, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error while decoding authPack, %s, %d\n", errorDescription, ret);
		return -1;
	}


	len = 0;
	ret = asn1_read_value(authPack, "clientPublicValue.subjectPublicKey", NULL, &len);
	if(ret != ASN1_MEM_ERROR) {
		printf("error when reading subjectPublicKey, %d\n", ret);
		return -1;
	}
	printf("public key length: %d\n", len);
	pubKey = malloc(len/8);
	ret = asn1_read_value(authPack, "clientPublicValue.subjectPublicKey", pubKey, &len);
	if(ret != ASN1_SUCCESS) {
		printf("error when reading subjectPublicKey, %d\n", ret);
		return -1;
	}

//	char * key;
//	key = (char *)pubKey;

	memcpy(ecdh_public_key,pubKey, len/8);

	free(der_padata);
	free(der_authPack);
	free(der_signedData);
	free(signedAuthPack);
	free(pubKey);

	return 0;
}


int create_as_req(char * cname, char * sname, char * realm, char * ecdh_public_key, char * nonce, char * as_req, int * as_req_size) {
	asn1_retCode ret;
	char * error = NULL;
	ASN1_TYPE def=ASN1_TYPE_EMPTY;	
	asn1_node message, pa_data, authPack, req_body, contentInfo, signedData;
	time_t now;
	struct tm * till_tm;
	struct tm * now_tm;
	char till[16];	

	char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	asn1_node dst_node;
	void *der_data = NULL;
	void *der_authPack = NULL;
	void *der_signedData = NULL;
	void *der_contentInfo = NULL;
	void *der_paData = NULL;
	int size = 0;
	


	ret = asn1_array2tree(kerberosV5spec2_asn1_tab, &def, error);
	if(ret) {
		printf("error: %s\n", error);
		return -1;
	}
	/*		CREATE FULL MESSAGE			*/
	ret = asn1_create_element(def, "KerberosV5Spec2.AS-REQ", &message);
	if(ret) {
		printf("error while creating element, %d\n", ret);
		return -1;
	}
	//	pvno = 5
	ret = asn1_write_value(message, "pvno", "5", 0 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	//	msg-type = 10 (AS-REQ) / 11 (AS-REP)
	ret = asn1_write_value(message, "msg-type", "10", 0 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	//	client name
	ret = asn1_write_value(message, "req-body.cname.name-type", "2", 0 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "req-body.cname.name-string", "NEW", 1 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "req-body.cname.name-string.?1", cname,strlen(cname) );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	//	realm
	ret = asn1_write_value(message, "req-body.realm",realm , strlen(realm) );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	//	server name
	ret = asn1_write_value(message, "req-body.sname.name-type", "2", 0 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "req-body.sname.name-string", "NEW", 1 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "req-body.sname.name-string.?1", sname,strlen(sname) );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	//	from
	char now_ch[16];
	time(&now);
	now_tm = gmtime(&now);
	strftime( now_ch,15 , "%Y%m%d%H%M%S", now_tm);
	strcat(now_ch, "Z");
	ret = asn1_write_value(message, "req-body.from", now_ch, 15);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	//	till -> expiration date of the ticket
	till_tm = gmtime(&now);
	till_tm->tm_mon += 1;
	strftime( till,15 , "%Y%m%d%H%M%S", till_tm);
	strcat(till, "Z");

	ret = asn1_write_value(message, "req-body.till", till, 15);	
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}


	//	kdc-options
	ret = asn1_write_value(message, "req-body.kdc-options", "\x00\x00\x00\x00", 32);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	//	nonce
	printf("nonce: %s\n", nonce);
	ret = asn1_write_value(message, "req-body.nonce", nonce, 0);	
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	//	etype
	ret = asn1_write_value(message, "req-body.etype", "NEW", 1);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "req-body.etype.?1", "11", 0);	
	if(ret) {
		printf("error while writing etype, %d\n", ret);
		return -1;
	}
	

	//	pa-kxover
	ret = asn1_write_value(message, "padata", "NEW", 1);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "padata.?1.padata-value", "pa-kxover", 9);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "padata.?1.padata-type", "28", 0);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	
	
	
	/*		Creating checksum of req-body	(needed for pkAuthenticator)	*/
	ret = asn1_create_element(def, "KerberosV5Spec2.KDC-REQ-BODY", &req_body);
	if(ret) {
		printf("error while creating element, %d\n", ret);
		return -1;
	}

	dst_node = asn1_find_node(message, "req-body");
	if(dst_node == NULL) puts("not find");


	ret = asn1_der_coding(dst_node,"req-body" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_data = malloc(size);

	ret = asn1_der_coding(dst_node, "req-body", der_data, &size, NULL);
	if(ret) {
		printf("error on second der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}
	
	
	

	/*	PA-PK-AS-REQ ENCODING	*/

	ret = asn1_create_element(def, "KerberosV5Spec2.PA-PK-AS-REQ", &pa_data);
	if(ret) {
		printf("error while creating pa-data, %d\n", ret);
		return -1;
	}
	

	// 	create AuthPack
	ret = asn1_create_element(def, "KerberosV5Spec2.AuthPack", &authPack);
	if(ret) {
		printf("error while creating authPack, %d\n", ret);
		return -1;
	}

	//	-> PKAuthenticator
	ret = asn1_write_value(authPack, "pkAuthenticator.ctime",now_ch ,15); 
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(authPack, "pkAuthenticator.cusec","0" ,0); 
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	
	ret = asn1_write_value(authPack, "pkAuthenticator.paChecksum", der_data, size);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(authPack, "pkAuthenticator.nonce", nonce, 0);	
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	//	-> clientPublicValue
	//	--> algorithm identifier: id-ecPublicKey

	ret = asn1_write_value(authPack, "clientPublicValue.algorithm.algorithm", "1.2.840.10045.2.1",17); 
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}


	ret = asn1_write_value(authPack, "clientPublicValue.algorithm.parameters.namedCurve", "1.2.840.10045.3.1.7",19);
	if(ret) {
		printf("error while writing algorithm parameters, %d\n", ret); 
		return -1;
	}

	//	->-> Elliptic Curve parameters
	printf("ecdh public key: %s, size: %d \n", ecdh_public_key, strlen(ecdh_public_key));
	ret = asn1_write_value(authPack, "clientPublicValue.subjectPublicKey", ecdh_public_key, strlen(ecdh_public_key)*8);
	if(ret) {
		printf("error while writing public key, %d", ret);
		return -1;
	}
	

	//	DER-Encoding authPack
	size = 0;
	ret = asn1_der_coding(authPack,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first authPack der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_authPack = malloc(size);

	ret = asn1_der_coding(authPack, "", der_authPack, &size, errorDescription);
	if(ret) {
		printf("error on second authPack der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}


	/*	CREATE SIGNED_AUTH_PACK		*/
	// 	-> Create SignedData
	ret = asn1_create_element(def, "KerberosV5Spec2.SignedData", &signedData);
	if(ret) {
		printf("error while creating signedData, %d\n", ret);
		return -1;
	}

	ret = asn1_write_value(signedData, "version", "1", 0);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(signedData, "encapContentInfo.eContentType", "1.3.6.1.5.2.3.1", 15);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	ret = asn1_write_value(signedData, "encapContentInfo.eContent", der_authPack, size);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	
	//	-> DER encoding SignedData
	size = 0;
	ret = asn1_der_coding(signedData,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first signedData der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_signedData = malloc(size);

	ret = asn1_der_coding(signedData, "", der_signedData, &size, errorDescription);
	if(ret) {
		printf("error on second signedData der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}

	//	-> Create ContentInfo
	ret = asn1_create_element(def, "KerberosV5Spec2.ContentInfo", &contentInfo);
	if(ret) {
		printf("error while creating content info, %d\n", ret);
		return -1;
	}

	ret = asn1_write_value(contentInfo, "contentType", "1.2.840.113549.1.7.2", 20);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	ret = asn1_write_value(contentInfo, "content", der_signedData, size);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	// 	DER-encoding contentInfo
	size = 0;
	ret = asn1_der_coding(contentInfo,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first contentInfo der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_contentInfo = malloc(size);

	ret = asn1_der_coding(contentInfo, "", der_contentInfo, &size, errorDescription);
	if(ret) {
		printf("error on second contentInfo der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}
	

	//	ADD DER-encoded ContentInfo to PA-PK-AS-REQ
	ret = asn1_write_value(pa_data, "signedAuthPack", der_contentInfo, size);
	if(ret) {
		printf("error while writing signedAuthPack, %d\n", ret);
		return -1;
	}
	

	//	DER-encoding PA-PK-AS-REQ
	size = 0;
	ret = asn1_der_coding(pa_data,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first pa-data der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_paData = malloc(size);

	ret = asn1_der_coding(pa_data, "", der_paData, &size, errorDescription);
	if(ret) {
		printf("error on second pa-data der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}

	// 	ADD pa-pk-as-req to main message
	ret = asn1_write_value(message, "padata", "NEW", 1);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "padata.?2.padata-type", "16", 0);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "padata.?2.padata-value",der_paData, size);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}


	//encode final request
	size = 0;
	ret = asn1_der_coding(message,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first message der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	printf("size of full message: %d\n", size);
	unsigned char data[size];
	*as_req_size = size;


	ret = asn1_der_coding(message, "", data, &size, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error on second message der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}
	

	memcpy(as_req, data, size);

	free(der_authPack);
	free(der_paData);
	free(der_contentInfo);
	free(der_signedData);
	free(der_data);


	return 0;
}


int create_as_rep(char * cname, char * realm, char * nonce, char * ecdh_public_key, char * as_req, int * as_req_size) {
	asn1_retCode ret;
	char * error = NULL;
	ASN1_TYPE def=ASN1_TYPE_EMPTY;	
	asn1_node message, pa_data, dhInfo, contentInfo, signedData;

	char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
	void *der_data = NULL;
	void *der_signedData = NULL;
	void *der_contentInfo = NULL;
	void *der_paData = NULL;
	void *der_dhInfo = NULL;
	int size = 0;
	


	ret = asn1_array2tree(kerberosV5spec2_asn1_tab, &def, error);
	if(ret) {
		printf("error: %s\n", error);
		return -1;
	}
	/*		CREATE FULL MESSAGE			*/
	ret = asn1_create_element(def, "KerberosV5Spec2.AS-REQ", &message);
	if(ret) {
		printf("error while creating element, %d\n", ret);
		return -1;
	}
	//	pvno = 5
	ret = asn1_write_value(message, "pvno", "5", 0 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	//	msg-type = 10 (AS-REQ) / 11 (AS-REP)
	ret = asn1_write_value(message, "msg-type", "11", 0 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	//	client name
	ret = asn1_write_value(message, "cname.name-type", "2", 0 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "cname.name-string", "NEW", 1 );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "cname.name-string.?1", cname,strlen(cname) );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	//	realm
	ret = asn1_write_value(message, "realm",realm , strlen(realm) );
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	

	//	pa-kxover
	ret = asn1_write_value(message, "padata", "NEW", 1);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "padata.?1.padata-value", "pa-kxover", 9);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "padata.?1.padata-type", "28", 0);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	
	
	
	/*	PA-PK-AS-REP ENCODING	*/

	ret = asn1_create_element(def, "KerberosV5Spec2.PA-PK-AS-REP", &pa_data);
	if(ret) {
		printf("error while creating pa-data, %d\n", ret);
		return -1;
	}
	
	/*	-> KDCDHKeyInfo		*/	
	ret = asn1_create_element(def, "KerberosV5Spec2.KDCDHKeyInfo", &dhInfo);
	if(ret) {
		printf("error while creating KDCDHKeyInfo, %d\n", ret);
		return -1;
	}

	/*	--> SubjectPublicKey		*/
	ret = asn1_write_value(dhInfo, "subjectPublicKey", ecdh_public_key, strlen(ecdh_public_key)*8);
	if(ret) {
		printf("error while writing subjectPublicKey, %d\n", ret);
		return -1;
	}

	/*	--> nonce		*/
	ret = asn1_write_value(dhInfo, "nonce", nonce, strlen(nonce));
	if(ret) {
		printf("error while writing nonce, %d\n", ret);
		return -1;
	}

	//	DER-Encoding authPack
	size = 0;
	ret = asn1_der_coding(dhInfo, "" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first authPack der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_dhInfo = malloc(size);

	ret = asn1_der_coding(dhInfo, "", der_dhInfo, &size, errorDescription);
	if(ret) {
		printf("error on second authPack der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}


	/*	CREATE SIGNED_DHInfo		*/
	// 	-> Create SignedData
	ret = asn1_create_element(def, "KerberosV5Spec2.SignedData", &signedData);
	if(ret) {
		printf("error while creating signedData, %d\n", ret);
		return -1;
	}

	ret = asn1_write_value(signedData, "version", "1", 0);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	//id-pkinit-DHKeyData
	ret = asn1_write_value(signedData, "encapContentInfo.eContentType", "1.3.6.1.5.2.3.2", 15);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	ret = asn1_write_value(signedData, "encapContentInfo.eContent", der_dhInfo, size);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	
	//	-> DER encoding SignedData
	size = 0;
	ret = asn1_der_coding(signedData,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first signedData der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_signedData = malloc(size);

	ret = asn1_der_coding(signedData, "", der_signedData, &size, errorDescription);
	if(ret) {
		printf("error on second signedData der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}

	//	-> Create ContentInfo
	ret = asn1_create_element(def, "KerberosV5Spec2.ContentInfo", &contentInfo);
	if(ret) {
		printf("error while creating content info, %d\n", ret);
		return -1;
	}

	ret = asn1_write_value(contentInfo, "contentType", "1.2.840.113549.1.7.2", 20);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	ret = asn1_write_value(contentInfo, "content", der_signedData, size);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}

	// 	DER-encoding contentInfo
	size = 0;
	ret = asn1_der_coding(contentInfo,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first contentInfo der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_contentInfo = malloc(size);

	ret = asn1_der_coding(contentInfo, "", der_contentInfo, &size, errorDescription);
	if(ret) {
		printf("error on second contentInfo der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}
	

	//	ADD DER-encoded ContentInfo to PA-PK-AS-REP
	ret = asn1_write_value(pa_data, "dhInfo.dhSignedData", der_contentInfo, size);
	if(ret) {
		printf("error while writing dhSignedData, %d\n", ret);
		return -1;
	}
	

	//	DER-encoding PA-PK-AS-REP
	size = 0;
	ret = asn1_der_coding(pa_data,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first pa-data der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	der_paData = malloc(size);

	ret = asn1_der_coding(pa_data, "", der_paData, &size, errorDescription);
	if(ret) {
		printf("error on second pa-data der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}

	// 	ADD pa-pk-as-rep to main message
	ret = asn1_write_value(message, "padata", "NEW", 1);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "padata.?2.padata-type", "17", 0);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}
	ret = asn1_write_value(message, "padata.?2.padata-value",der_paData, size);
	if(ret) {
		printf("error while writing value, %d\n", ret);
		return -1;
	}


	//encode final request
	size = 0;
	ret = asn1_der_coding(message,"" , NULL, &size, errorDescription);
	if( ret != ASN1_MEM_ERROR) {
		printf("error on first message der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return ret;
	}
	printf("size of full message: %d\n", size);
	unsigned char data[size];
	*as_req_size = size;


	ret = asn1_der_coding(message, "", data, &size, errorDescription);
	if(ret != ASN1_SUCCESS) {
		printf("error on second message der coding, %d, len: %d, error Description: %s\n", ret, size, errorDescription);
		return -1;
	}
	

	memcpy(as_req, data, size);

	free(der_dhInfo);
	free(der_paData);
	free(der_contentInfo);
	free(der_signedData);
	free(der_data);


	return 0;
}
