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

#ifdef DEBUG
#include <stdio.h>
#endif

#include <time.h>

#include <krb5/krb5.h>
#include <mit-krb5/profile.h>

#include <quick-der/api.h>

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
#define NUM_ENCTYPES 21
static struct enctype enctypes_array [21] = {
	1,	"des-cbc-crc",			true,	false,
	2,	"des-cbc-md4",			true,	false,
	3,	"des-cbc-md5",			true,	false,
	5,	"des3-cbc-md5",			true,	false,
	7,	"des3-cbc-sha1",		true,	false,
	9,	"dsaWithSHA1-CmsOID",		false,	false,
	10,	"md5WithRSAEncryption-CmsOID",	false,	false,
	11,	"sha1WithRSAEncryption-CmsOID",	false,	false,
	12,	"rc2CBC-EnvOID",		false,	false,
	13,	"rsaEncryption-EnvOID",		false,	false,
	14,	"rsaES-OAEP-ENV-OID",		false,	false,
	15,	"des-ede3-cbc-Env-OID",		false,	false,
	16,	"des3-cbc-sha1-kd",		true,	false,
	17,	"aes128-cts-hmac-sha1-96",	false,	true,
	18,	"aes256-cts-hmac-sha1-96",	false,	true,
	19,	"aes128-cts-hmac-sha256-128",	false,	true,
	20,	"aes256-cts-hmac-sha384-192",	false,	true,
	23,	"rc4-hmac",			true,	false,
	24,	"rc4-hmac-exp",			true,	false,
	25,	"camellia128-cts-cmac",		false,	true,	// hash length?
	26,	"camellia256-cts-cmac",		false,	true,	// hash length?
};
const struct enctype *enctypes = enctypes_array;


/* Store encryption types (etypes) in a DER INTEGER before
 * composing the SEQUENCE OF EncryptionType that goes into
 * the KX-OFFER.etypes list.  This is done once, while
 * running kerberos_init(), and is after then shared.  The
 * following buffers are needed to store enough bytes for
 * the transformation.
 */
static char *etypes_names [NUM_ENCTYPES + 1];  // NULL terminated
static uint8_t seqof_etype [7 + 6 * NUM_ENCTYPES];  // SEQ,?lenlen,len<=5,*(INT,len=1,val<=4)
static union dernode dercrs_seqof_etypes;


/* Given a string with a selection, initialise the various
 * static storage structures.  The selection may be NULL to
 * select anything permissible and not deprecated.  If not,
 * encryption type names are assumed separated by spaces
 * and commas.  Note that there is a requirement of having
 * the etypes sorted in the SEQUENCE OF EncryptionType.
 */
static void kerberos_init_etypes (char *seln) {
	//
	// Intermediate storage structures
	der_buf_int32_t etypebuf [NUM_ENCTYPES];
	struct dercursor der_crs_int32 [NUM_ENCTYPES];
	derwalk pack_etypes [1 + NUM_ENCTYPES + 2];  // ENTER,*INTEGER,LEAVE,END
	//
	// Iterate over the enctypes_array and selectively add
	int outp = 0;
	int inp;
	for (inp = 0; inp < NUM_ENCTYPES; inp++) {
		//
		// Test if we want the current name
		if (!enctypes_array [inp].crossover) {
			continue;
		}
		char *name = enctypes_array [inp].name;
		if ((seln == NULL) && (enctypes_array [inp].deprecated)) {
			continue;
		}
		char *seln2 = (seln != NULL) ? seln : name;
		char *etpos = strstr (seln2, name);
		if (etpos == NULL) {
			continue;
		}
		if ((etpos != seln2) && (etpos [-1] != ',') && (etpos [-1] != ' ')) {
			continue;
		}
		char term = etpos [strlen (name)];
		if ((term != '\0') && (term != ',') && (term != ' ')) {
			continue;
		}
		//
		// Test if the enctype is acceptable / advisable
		if (enctypes_array [inp].deprecated) {
			fprintf (stderr, "Warning: KXOVER uses deprecated algorithm \"%s\"\n", name);
		}
		//
		// Add the enctype to the various arrays
		etypes_names [outp] = name;
		der_crs_int32 [outp] = der_put_int32 (etypebuf [outp], enctypes_array [inp].code);
		pack_etypes [outp] = DER_PACK_STORE | DER_TAG_INTEGER;
		outp++;
	}
	//
	// Close off and render all structures
	etypes_names [outp] = NULL;
	pack_etypes [outp] = DER_PACK_END;
	dercrs_seqof_etypes.wire.derlen = der_pack (pack_etypes, der_crs_int32, NULL);
	dercrs_seqof_etypes.wire.derptr = seqof_etype;
	der_pack (pack_etypes, der_crs_int32, seqof_etype + dercrs_seqof_etypes.wire.derlen);
}


/* Return a prepackaged form that can be used as SEQUENCE OF EncryptionType,
 * and included in KX-OFFER messages.  Quick DER cannot handle variable-sized
 * structures, so this must be prepared.
 *
 * The returned values are shared and must not be freed by the caller.
 */
const union dernode kerberos_seqof_enctypes (void) {
	return dercrs_seqof_etypes;
}


static const struct kerberos_config default_config = {
	//HUH?!?// .certified_client_hostname = NULL,
	.crossover_enctypes = etypes_names,
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
 * will not be NUL terminated, and its length will always be
 * the fixed value KERBEROS_TIME_STRLEN.
 *
 * Call this function with a buffer initialised to suitable
 * values for .derptr and .derlen.  There will be no problems
 * due to trailing NUL characters written.
 *
 * Note that TZ=UTC thanks to kerberos_init().
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_set (time_t tstamp, dercursor out_krbtime) {
	struct tm tmp_tm;
	if ((out_krbtime.derptr == NULL) || (out_krbtime.derlen != KERBEROS_TIME_STRLEN)) {
		errno = EINVAL;
		return false;
	}
	localtime_r ((const time_t *) &tstamp, &tmp_tm);
	char mid [KERBEROS_TIME_STRLEN + 1];
	strftime (mid, sizeof (mid), KERBEROS_TIME_FORMAT, &tmp_tm);
	memcpy (out_krbtime.derptr, mid, KERBEROS_TIME_STRLEN);
	return true;
}


/* This function is like kerberos_time_set() but it uses the
 * current wallclock time instead of a user-supplied time.
 * The tstamp value can be output, but it may be NULL if this
 * is not desired.
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_set_now (time_t *opt_out_tstamp, dercursor out_krbtime) {
	time_t now = time (opt_out_tstamp);
	if (now == (time_t) -1) {
		/* errno is set to EOVERFLOW */
		return false;
	}
	return kerberos_time_set (now, out_krbtime);
}


/* Get a time_t value from a KerberosTime string.  The string
 * is not assumed to be NUL-terminated, but its length should
 * match the format.
 *
 * Note that TZ=UTC thanks to kerberos_init().
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_get (dercursor krbtime, time_t *out_tstamp) {
	char *strptime ();
	char mid [KERBEROS_TIME_STRLEN + 1];
	if (krbtime.derlen != KERBEROS_TIME_STRLEN) {
		goto bailout_EINVAL;
	}
	memcpy (mid, krbtime.derptr, KERBEROS_TIME_STRLEN);
	mid [KERBEROS_TIME_STRLEN] = '\0';
	struct tm tmp_tm;
	memset (&tmp_tm, 0, sizeof (tmp_tm));
	if (strptime (mid, KERBEROS_TIME_FORMAT, &tmp_tm) == NULL) {
		goto bailout_EINVAL;
	}
	*out_tstamp = mktime (&tmp_tm);
	return true;
bailout_EINVAL:
	errno = EINVAL;
	return false;
}


/* This function is like kerberos_time_get() but it adds a
 * Check that a time matches well enough with the clock time,
 * in practice meaning a window of about 5 minutes around the
 * system's idea of time.
 *
 * Return true on success, or false with errno set otherwise.
 */
bool kerberos_time_get_check_now (dercursor krbtime, time_t *out_tstamp) {
	if (!kerberos_time_get (krbtime, out_tstamp)) {
		return false;
	}
	time_t now;
	now = time (NULL);
	if (now == (time_t) -1) {
		/* errno is set to EOVERFLOW */
		return false;
	}
	if ((*out_tstamp < now - 2*60) || (*out_tstamp > now + 3*60)) {
		errno = ETIMEDOUT;
		return false;
	}
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
	//
	// Calculate lists of encryption types
	kerberos_init_etypes (NULL);  /* TODO: config string */
	//
	// Success
	return true;
}


/* Cleanup what was allocated for the Kerberos environment.
 */
bool kerberos_fini (void) {
	krb5_free_context (krb5_ctx);
	return true;
}


