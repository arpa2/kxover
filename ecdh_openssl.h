#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>


EC_KEY * generateKeys();
int getPublicKey(EC_KEY * key, char * public_key_hex);
int generateSecret(char * remote_key_hex, EC_KEY * key, char * secret, int * len);
