#include <k5-int.h>
#include "util.h"
#include "lookup.h"
#include <sys/socket.h>
#include <openssl/ec.h>
#include "tlsa_openssl.h"
#include "asn1.h"
#include "request_list.h"


int process_tgs_req( krb5_data pkt);
