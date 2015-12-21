#include "util.h"

char *
data2string (krb5_data *d)
{
    char *s;
    s = malloc(d->length + 1);
    if (s) {
        if (d->length > 0)
            memcpy(s, d->data, d->length);
        s[d->length] = 0;
    }
    return s;
}
