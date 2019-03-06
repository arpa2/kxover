/* mitkrb5.c -- Interface to Kerberos; in this module, implement MIT krb5.
 *
 * This module implements generic API calls that link to Kerberos.
 * In the case of this module, the underlying Kerberos stack is the MIT krb5
 * implementation.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdbool.h>
#include <stdint.h>

#include <time.h>

#include <krb5/krb5.h>
#include <mit-krb5/profile.h>

#include "kerberos.h"



/* Encryption types as standardised by IANA.
 * Source: https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml
 *
 * Deprecation according to the source is reason for exclusion
 * below.  Deprecation by IANA is subject to change, and will be
 * incorporated in the table below to protect future crossover.
 *
 * Furthermore, not all algorithms are marked for crossover.
 * The reason they are added here is for completeness sake;
 * to be able to parse strings and say why an enctype will not
 * be used.
 *
 * There is little reason to be backward-compatible with a new
 * protocol, so crossover sets a higher norm.  This seems like a
 * good idea, because much can be hung from crossover keys; but
 * it is good to also realise that we do also use TLS during the
 * setup, so this is not much more special than a manually agreed
 * key for realm crossover.
 */
static struct enctype enctypes_array [] = {
	1,	"des-cbc-crc",			false,	false,
	2,	"des-cbc-md4",			false,	false,
	3,	"des-cbc-md5",			false,	false,
	5,	"des3-cbc-md5",			false,	false,
	7,	"des3-cbc-sha1",		false,	false,
	9,	"dsaWithSHA1-CmsOID",		true,	false,
	10,	"md5WithRSAEncryption-CmsOID",	true,	false,
	11,	"sha1WithRSAEncryption-CmsOID",	true,	false,
	12,	"rc2CBC-EnvOID",		true,	false,
	13,	"rsaEncryption-EnvOID",		true,	false,
	14,	"rsaES-OAEP-ENV-OID",		true,	false,
	15,	"des-ede3-cbc-Env-OID",		true,	false,
	16,	"des3-cbc-sha1-kd",		false,	false,
	17,	"aes128-cts-hmac-sha1-96",	true,	true,
	18,	"aes256-cts-hmac-sha1-96",	true,	true,
	19,	"aes128-cts-hmac-sha256-128",	true,	true,
	20,	"aes256-cts-hmac-sha384-192",	true,	true,
	23,	"rc4-hmac",			false,	false,
	24,	"rc4-hmac-exp",			false,	false,
	25,	"camellia128-cts-cmac",		true,	true,
	26,	"camellia256-cts-cmac",		true,	true,
	/* End marker has (code==0) && (name==NULL) */
	0,	NULL,				false,	false
};
const struct enctype *enctypes = enctypes_array;


char *kxetypes [] = {
	"aes256-cts-hmac-sha384-192",
	"aes256-cts-hmac-sha256-128-128",
	"camellia256-cts-cmac",
	NULL
};

static const struct kerberos_config default_config = {
	//HUH?!?// .certified_client_hostname = NULL,
	.crossover_enctypes = kxetypes,
	.kdc_hostname = "::1",
	.kdc_port = 88,
	.kvno_offset = 20000,
	.kvno_scheme = "%m%d0",
	.kvno_maxtry = 3,
	.crossover_lifedays = 100,
};


static krb5_context krb5_ctx;


/* Load the configuration.  As a convenience, this is taken from the
 * normal configuration setup for Kerberos.  Specifically, we introduce a
 * section "[kxover]" to be used in ${KRB5_CONFIG-/etc/krb5.conf}:
 *
 * [kxover]
 * #NOTYET# certified_client_hostname = kdc.example.com
 * #NOTYET# permitted_enctypes = aes256-cts-hmac-sha384-192,aes256-cts-hmac-sha1-96,camellia256-cts-cmac
 * #NOTYET# kdc_address = ::1
 * #NOTYET# kdc_port = 88
 * #NOTYET# kvno_offset = 20000
 * #NOTYET# kvno_scheme = %m%d0
 * #NOTYET# kvno_maxtry = 3
 * #NOTYET# crossover_lifedays = 100
 */
const struct kerberos_config *kerberos_config (void) {
	//krb5_get_profile// http://web.mit.edu/kerberos/krb5-current/doc/appdev/refs/api/krb5_get_profile.html
	//profile_get_type// https://github.com/krb5/krb5/blob/09c9b7d6f64767429e90ad11a529e6ffa9538043/src/util/profile/profile.hin
	return &default_config;
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
	if (krb5_c_random_make_octets (krb5_ctx, &data) != 0) {
		errno = ENOSYS;
		return false;
	}
	return true;
}


/* Install a new krbgtgt/SERVICE.REALM@CLIENT.REALM with the given key.
 *
 * Return true on success, or false with errno set on failure.
 */
bool install_crossover_key (int TODO) {
	errno = ENOSYS;
	return false;
}


/* Lookup the local KDC hostname for a given realm.
 *
 * Return an empty string if none is known.
 */
const struct dercursor kerberos_localrealm2hostname (struct dercursor local_realm) {
	//TODO// An actual host name might be nice...
	struct dercursor retval = { .derptr="localhost", .derlen=9 };
	return retval;
}


/* Set a KerberosTime from a time_t value.  The output string
 * will be NUL terminated, but its length will always be the
 * fixed value KERBEROS_TIME_LEN.
 *
 * Note that TZ=UTC thanks to kerberos_init().
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_set (time_t tstamp, char out_krbtime [KERBEROS_TIME_STORAGE]) {
	struct tm tmp_tm;
	localtime_r ((const time_t *) &tstamp, &tmp_tm);
	strftime (out_krbtime, KERBEROS_TIME_STORAGE, KERBEROS_TIME_FORMAT, &tmp_tm);
	return true;
}


/* Get a time_t value from a KerberosTime string.  The string
 * is assumed to be NUL-terminated, even if its length is
 * fixed and predictable.
 *
 * Note that TZ=UTC thanks to kerberos_init().
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_get (const char krbtime [KERBEROS_TIME_STORAGE], time_t *out_tstamp) {
	char *strptime ();
	if (strlen (krbtime) != KERBEROS_TIME_STRLEN) {
		errno = EINVAL;
		return false;
	}
	struct tm tmp_tm;
	memset (&tmp_tm, 0, sizeof (tmp_tm));
	if (strptime (krbtime, KERBEROS_TIME_FORMAT, &tmp_tm) == NULL) {
		errno = EINVAL;
		return false;
	}
	*out_tstamp = mktime (&tmp_tm);
	return true;
}


/* Setup what is desired for the Kerberos environment.
 *
 * Since we use date/time functions and these are only standardised
 * dependently on $TZ, we shall set this variable to "UTC".
 *
 * Yeah, this is rather an amiss in the POSIX standards...
 */
bool kerberos_init (void) {
	//
	// Set TZ=UTC so the POSIX time functions make /some/ sense
	char *tz_old = getenv ("TZ");
	if ((tz_old == NULL) || (strcmp (tz_old, "UTC") != 0)) {
		if (setenv ("TZ", "UTC", 1) == -1) {
			/* errno is set by setenv() */
			return false;
		}
	}
	//
	// Open a Kerberos context
	if (krb5_init_context (&krb5_ctx) != 0) {
		return false;
	}
	return true;
}


/* CLeanup what was allocated for the Kerberos environment.
 */
bool kerberos_fini (void) {
	krb5_free_context (krb5_ctx);
	return true;
}


