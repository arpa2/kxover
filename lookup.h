#include <stdio.h>
#include <getdns/getdns.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

int lookupSRV(char* query, char* target, int* port);

int lookupTXT(char* query, int max, char* results[], int* size);

