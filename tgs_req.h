#include <k5-int.h>
#include "util.h"
#include "lookup.h"
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <arpa/inet.h>


int process_tgs_req( krb5_data pkt);
