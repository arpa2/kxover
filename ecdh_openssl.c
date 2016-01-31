#include "ecdh_openssl.h"


int generateKeys(char * public_key_hex) {
	int ret;
	EC_GROUP * ec_group;
	EC_POINT * public_key;
	EC_KEY * key;
	
	ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if(ec_group == NULL) {
		puts("error when generating group");
		return -1;
	}

	key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if( key == NULL) {
		puts("error when generating the curve object");
		return -1;
	}

	ret = EC_KEY_generate_key(key);
	if( ret != 1) { 
		puts("error when generating key");
		return -1;
	}

	public_key = EC_KEY_get0_public_key(key);
	if(public_key == NULL) {
		puts("error getting public key");
		return -1;
	}

	char * tmp;
	tmp = EC_POINT_point2hex(ec_group, public_key, POINT_CONVERSION_COMPRESSED, NULL);
	strcpy(public_key_hex, tmp);

	return 0;
}


