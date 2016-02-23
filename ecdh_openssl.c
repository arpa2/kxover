#include "ecdh_openssl.h"


static void *KDF1_SHA1(const void *in, size_t inlen, void *out,
                       size_t *outlen)
{
    if (*outlen < SHA_DIGEST_LENGTH)
        return NULL;
    *outlen = SHA_DIGEST_LENGTH;
    return SHA1(in, inlen, out);
}


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

int generateSecret(char * remote_key_hex, char * public_key_hex, char * secret) {
	EC_POINT * remote_key;
	EC_GROUP * ec_group;
	EC_KEY * key;
	int field_size, secret_len, ret;
	
	printf("remote key hex: %s\n", remote_key_hex);

	ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if(ec_group == NULL) {
		puts("error when generating group");
		return -1;
	}
	

	puts("group done\n");
	remote_key = EC_POINT_hex2point(ec_group, remote_key_hex,remote_key,NULL);
	if(remote_key == NULL) {
		puts("error when converting point");
		return -1;
	}
	
	key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if( key == NULL) {
		puts("error when generating the key pair");
		return -1;
	}

	ret = EC_KEY_generate_key(key);
	if(ret != 1) {
		puts("error when generating key");
		return -1;
	}
	

	field_size = EC_GROUP_get_degree(ec_group);
	secret_len = (field_size+7)/8;
	printf("secret_len: %d\n", secret_len);
	char * sec;
	sec = OPENSSL_malloc(secret_len);

	secret_len = ECDH_compute_key(sec, secret_len, remote_key, key, NULL);

	if(secret_len <= 0) {
		puts("error while computing shared secret");
		perror("shared secret");
		return -1;
	}
	hexdump(sec, strlen(sec));

	printf("shared secret. hex: %04X, int: %d, string: %s, strlen: %d\n", sec, sec, sec, strlen(sec));
	memcpy(secret, sec, strlen(sec));

	return 0;
}


