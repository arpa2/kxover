#include <getdns/getdns.h>
#include <k5-int.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include "lookup.h"

int checkTLSA(getdns_list * tlsas, char* target, int port);
