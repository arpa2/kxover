#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>

#include <errno.h>

#include <krb5/krb5.h>


#if 1

#include "kerberos.h"

#else

static krb5_context krb5_ctx;

/* Setup what is desired for the Kerberos environment.
 */
bool kerberos_init (void) {
	//
	// Open a Kerberos context
	if (krb5_init_context (&krb5_ctx) != 0) {
		return false;
	}
	return true;
}


/* Cleanup what was allocated for the Kerberos environment.
 */
bool kerberos_fini (void) {
	krb5_free_context (krb5_ctx);
	return true;
}

/* Use Kerberos to generate pseudo-random bytes.
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_prng (uint8_t *outptr, uint16_t outlen) {
	krb5_data data;
	//DUNNO// data.magic = ...;
	data.length = outlen;
	data.data = outptr;
	krb5_error_code kerrno = krb5_c_random_make_octets (krb5_ctx, &data);
	if (kerrno != 0) {
		const char *kerrstr = krb5_get_error_message (krb5_ctx, kerrno);
		printf ("ERROR: %s\n", kerrstr);
		krb5_free_error_message (krb5_ctx, kerrstr);
		errno = ENOSYS;
		return false;
	}
	return true;
}

#endif

int main (int argc, char *argv[]) {
	uint8_t salt [32];
	assert (kerberos_init ());
	if (!kerberos_prng (salt, sizeof (salt))) {
		perror ("Entropy failure");
		exit (1);
	}
	char *comma = "";
	int i;
	for (i=0; i<sizeof (salt); i++) {
		printf ("%s%02x", comma, salt [i]);
		comma = " ";
	}
	printf ("\n");
	assert (kerberos_fini ());
	exit (0);
}
