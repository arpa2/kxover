#include <k5-int.h>
#include "util.h"
#include "lookup.h"
#include <sys/socket.h>
#include "tlsa_openssl.h"
#include "asn1.h"


int process_tgs_req( krb5_data pkt);
