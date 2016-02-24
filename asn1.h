#include "array.h"
#include "util.h"
#include <libtasn1.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



int extract_public_key(char * data, int size, char * ecdh_public_key, char * nonce); 
int create_as_req(char * cname, char * sname, char * realm, char * ecdh_public_key, char * as_req, int * as_req_size);
int create_as_rep(char * cname, char * realm, char * nonce, char * ecdh_public_key, char * as_req, int * as_req_size);
