#include <krb5.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

char *data2string(krb5_data *d);

void hexdump(void *mem, unsigned int len);
