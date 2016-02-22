#include <string.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>


int generateKeys(char *public_key_hex);
int generateSecret(char * remote_key_hex, char * public_key_hex, char * secret);
