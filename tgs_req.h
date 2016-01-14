#include <k5-int.h>
#include "util.h"
#include "lookup.h"
#include <sys/socket.h>
#include "tlsa_openssl.h"


int process_tgs_req( krb5_data pkt);
