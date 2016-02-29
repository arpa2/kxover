#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/ec.h>


struct request_list * create_list(char * target, EC_KEY * key, char * nonce);

struct request_list * add_to_list(char * target, EC_KEY * key, char * nonce);

struct request_list * search(char * target, struct request_list **prev);

int delete_from_list(char * target);

void print_list();
