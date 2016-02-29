#include "ecdh_openssl.h"



EC_KEY * generateKeys() {
	int ret;
	EC_GROUP * ec_group;
	EC_KEY * key;
	
	ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if(ec_group == NULL) {
		puts("error when generating group");
		return NULL;
	}

	key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if( key == NULL) {
		puts("error when generating the curve object");
		return NULL;
	}

	ret = EC_KEY_generate_key(key);
	if( ret != 1) { 
		puts("error when generating key");
		return NULL;
	}

	return key;

}

int getPublicKey(EC_KEY * key, char * public_key_hex) {
	EC_POINT * public_key;
	EC_GROUP * ec_group;

	ec_group = EC_KEY_get0_group(key);

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

int generateSecret(char * remote_key_hex, EC_KEY * key, char * secret, int *len) {
	EC_POINT * remote_key;
	EC_GROUP * ec_group;
	int field_size, secret_len;
	

	ec_group = EC_KEY_get0_group(key);
	if(ec_group == NULL) {
		puts("error when generating group");
		return -1;
	}
	

	remote_key = EC_POINT_hex2point(ec_group, remote_key_hex,remote_key,NULL);
	if(remote_key == NULL) {
		puts("error when converting point");
		return -1;
	}
	
	field_size = EC_GROUP_get_degree(ec_group);
	secret_len = (field_size+7)/8;
	printf("secret_len: %d\n", secret_len);
	char * sec;
	size_t sharedsecret_len;
	sec = OPENSSL_malloc(secret_len);

	sharedsecret_len = ECDH_compute_key(sec, secret_len, remote_key, key, NULL);

	if(secret_len <= 0) {
		puts("error while computing shared secret");
		perror("shared secret");
		return -1;
	}
	
	uint8_t md[32];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, sec, secret_len);
	SHA256_Final(md, &ctx);
	
	char * hexout;
	hexout = malloc(65);
	if(hexout == NULL) {
		puts("error while allocating");
		return -1;
	}

	sprintf(hexout, "%02x", md[0]);
	int i;
	for(i = 1; i < 32; i++) {
		sprintf(hexout+strlen(hexout), "%02x", md[i]);
	}
	*len = 64;

	
	memcpy(secret, hexout,65);

	return 0;
}


