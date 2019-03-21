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
#include <assert.h>
#include <stdio.h>

#include <time.h>

#include <krb5/krb5.h>
#include <mit-krb5/profile.h>
#include <kadm5/admin.h>

/* Fixed default settings... chances are, _PUBLIC_SERVICE needs a realm */
#define KADM5_KXOVER_PUBLIC_SERVICE "kxover/public"
#define KADM5_KXOVER_PUBLIC_KEYTAB  "/etc/kxover/public.keytab"

#include <quick-der/api.h>

#include "kerberos.h"


#ifdef DEBUG
#  define DPRINTF printf
#else
#  define DPRINTF(...)
#endif


// #include <mit-krb5/kdb.h>
// #if KRB5_KDB_API_VERSION != 9
// #error "MIT krb5 API version for <kdb.h> has changed to indicate incompatible changes"
// #endif



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
	1,	"des-cbc-crc",			true,	false, 0,
	2,	"des-cbc-md4",			true,	false, 0,
	3,	"des-cbc-md5",			true,	false, 0,
	5,	"des3-cbc-md5",			true,	false, 0,
	7,	"des3-cbc-sha1",		true,	false, 0,
	9,	"dsaWithSHA1-CmsOID",		false,	false, 0,
	10,	"md5WithRSAEncryption-CmsOID",	false,	false, 0,
	11,	"sha1WithRSAEncryption-CmsOID",	false,	false, 0,
	12,	"rc2CBC-EnvOID",		false,	false, 0,
	13,	"rsaEncryption-EnvOID",		false,	false, 0,
	14,	"rsaES-OAEP-ENV-OID",		false,	false, 0,
	15,	"des-ede3-cbc-Env-OID",		false,	false, 0,
	16,	"des3-cbc-sha1-kd",		true,	false, 0,
	17,	"aes128-cts-hmac-sha1-96",	false,	true, 16,
	18,	"aes256-cts-hmac-sha1-96",	false,	true, 32,
	19,	"aes128-cts-hmac-sha256-128",	false,	true, 16,
	20,	"aes256-cts-hmac-sha384-192",	false,	true, 32,
	23,	"rc4-hmac",			true,	false, 0,
	24,	"rc4-hmac-exp",			true,	false, 0,
	25,	"camellia128-cts-cmac",		false,	true, 16,	// hash length?
	26,	"camellia256-cts-cmac",		false,	true, 32,	// hash length?
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
static size_t usable_salt;


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
	size_t saltlen = 0;
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
		if (enctypes_array [inp].random4key == 0) {
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
		if (saltlen < enctypes_array [inp].random4key) {
			saltlen = enctypes_array [inp].random4key;
		}
		etypes_names [outp] = name;
		der_crs_int32 [outp] = der_put_int32 (etypebuf [outp], enctypes_array [inp].code);
		pack_etypes [outp] = DER_PACK_STORE | DER_TAG_INTEGER;
		outp++;
	}
	//
	// Close off and render all structures
	if (usable_salt > MAX_SALT_BYTES) {
		usable_salt = MAX_SALT_BYTES;
	}
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


/* Return the number of bytes of salt to use.  The result will not exceed
 * MAX_SALT_BYTES.
 *
 * This function does not fail.
 */
const size_t kerberos_salt_bytes (void) {
	return usable_salt;
}


static const struct kerberos_config default_config = {
	.certified_client_hostname = NULL,
	.crossover_enctypes = NULL,
	.crossover_enctypev = etypes_names,
	.kdc_hostname = "::1",
	.kdc_port = 88,
	//NOTYET// .kvno_offset = 20000,
	//NOTYET// .kvno_scheme = "%m%d0",
	//NOTYET// .kvno_maxtry = 3,
	.crossover_lifedays = 100,
	.kxover_keytab = KADM5_KXOVER_PUBLIC_KEYTAB,
	.kxover_name   = KADM5_KXOVER_PUBLIC_SERVICE,
	.kxover_realm = "UNICORN.DEMO.ARPA2.ORG",
};


static krb5_context krb5_ctx;
static krb5_context kadm5_ctx;
static void *kadm5_hdl;


/* Internal routine for error handling.  When no error has
 * occurred, return true and do nothing.  When an error
 * did occur, print it and return false.
 */
static bool _krb5_handle_error (int as_errno, krb5_error_code kerrno) {
	if (kerrno != 0) {
		const char *kerrstr = krb5_get_error_message (krb5_ctx, kerrno);
		fprintf (stderr, "ERROR: %s\n", kerrstr);
		krb5_free_error_message (krb5_ctx, kerrstr);
		errno = as_errno;
		return false;
	}
	return true;
}


/* Load the configuration.  As a convenience, this is taken from the
 * normal configuration setup for Kerberos.  Specifically, we introduce a
 * section "[kxover]" to be used in ${KRB5_CONFIG-/etc/krb5.conf}:
 *
 * Loading occurs once, upon first call.  Entries that are not found
 * are kept to their default values.
 *
 * [kxover]
 * 	certified_client_hostname = kdc.example.com
 * 	crossover_enctypes = aes256-cts-hmac-sha384-192,aes256-cts-hmac-sha1-96,camellia256-cts-cmac
 * 	#NOTHERE# kdc_address = ::1
 * 	#NOTHERE# kdc_port = 88
 * 	#NOTYET# kvno_offset = 20000
 * 	#NOTYET# kvno_scheme = %m%d0
 * 	#NOTYET# kvno_maxtry = 3
 *	crossover_lifedays = 100
 *	kxover_keytab = KADM5_KXOVER_PUBLIC_KEYTAB
 *	kxover_name   = KADM5_KXOVER_PUBLIC_SERVICE
 *	kxover_realm  = (default)
 *
 * The agreeable crossover_enctypes end up in crossover_enctypev, an
 * inferred member of the structure with configuration information.
 *
 * TODO: Is /etc/krb5.conf good, or is /etc/krb5kdc/kdc.conf better?
 */
const struct kerberos_config *kerberos_config (void) {
	//krb5_get_profile// http://web.mit.edu/kerberos/krb5-current/doc/appdev/refs/api/krb5_get_profile.html
	//profile_get_type// https://github.com/krb5/krb5/blob/09c9b7d6f64767429e90ad11a529e6ffa9538043/src/util/profile/profile.hin
	static struct kerberos_config retval_config;
	static bool first_call = TRUE;
	if (first_call) {
		memcpy (&retval_config, &default_config, sizeof (retval_config));
		profile_t profile = NULL;
		if (!_krb5_handle_error (EINVAL, krb5_get_profile (krb5_ctx, &profile))) {
			DPRINTF ("Failed to open profile from the current krb5_context\n");
			return NULL;
		}
		profile_get_string (profile,
			"kxover", "certified_client_hostname", NULL,
			default_config.certified_client_hostname,
			&retval_config.certified_client_hostname);
		profile_get_string (profile,
			"kxover", "crossover_enctypes", NULL,
			default_config.crossover_enctypes,
			&retval_config.crossover_enctypes);
		profile_get_integer (profile,
			"kxover", "crossover_lifedays", NULL,
			default_config.crossover_lifedays,
			&retval_config.crossover_lifedays);
		profile_get_string (profile,
			"kxover", "kxover_keytab", NULL,
			default_config.kxover_keytab,
			&retval_config.kxover_keytab);
		profile_get_string (profile,
			"kxover", "kxover_name", NULL,
			default_config.kxover_name,
			&retval_config.kxover_name);
		profile_get_string (profile,
			"kxover", "kxover_realm", NULL,
			default_config.kxover_realm,
			&retval_config.kxover_realm);
		profile_release (profile);
DPRINTF ("[kxover] certified_client_hostname = \"%s\"\n", retval_config.certified_client_hostname);
DPRINTF ("[kxover] crossover_enctypes        = \"%s\"\n", retval_config.crossover_enctypes       );
DPRINTF ("[kxover] crossover_lifedays        =  %d\n",    retval_config.crossover_lifedays       );
DPRINTF ("[kxover] kxover_keytab             = \"%s\"\n", retval_config.kxover_keytab            );
DPRINTF ("[kxover] kxover_name               = \"%s\"\n", retval_config.kxover_name              );
DPRINTF ("[kxover] kxover_realm              = \"%s\"\n", retval_config.kxover_realm             );
		retval_config.crossover_enctypev = etypes_names;
		first_call = FALSE;
	}
	return &retval_config;
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
	return _krb5_handle_error (ENOSYS, krb5_c_random_make_octets (
			krb5_ctx, &data));
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


/* Internal function to retrieve the most recent key with the
 * targeted kvno and etype.  The search is limited to relatively
 * recent keys, as the intention is to check if we have to ban
 * a client until a later time.
 *
 * This helps to implement the hard-wired local policy that
 * formats kvno as MMDDS: month MM, month-day DD, serial S.
 *
 * A special case happens when client and service share the KDC.
 * In this case the client will find its newly generated key
 * already inserted.  If this happens, it can be safely concluded
 * from a match on the binary key material.  CALLER RESPONSIBLE.
 *
 * Return NULL when nothing recent seems applicable, or the most
 * recent kadm5_key_data otherwise.
 */
static krb5_key_data *_find_recent_key (kadm5_principal_ent_t entry,
				krb5_kvno kvno, krb5_enctype enctype) {
	//
	// Construct a maximum key for today
	krb5_kvno last = kvno - (kvno % 10) + 9;
	//
	// Construct a minimum key for yesterday
	krb5_kvno yday = kvno - (kvno % 10) - 10;
	if (yday < 1000) {
		/* Wrap around the year */
		yday = 12000;
	} else if (yday % 1000 > 319) {
		/* Wrap around the month, not the year */
		yday -= yday % 1000;
	}
	//
	// Iterate over keys to find the latest
	krb5_key_data *found = NULL;
	krb5_int16 nk = entry->n_key_data;
	krb5_key_data *key = entry->key_data;
	key--;
	while (key++, nk-- > 0) {
		/* Check for a matching enctype */
		if (key->key_data_type [0] != enctype) {
			continue;
		}
		/* Skip keys after the current */
		if (key->key_data_kvno > last) {
			continue;
		}
		/* Skip keys before yday */
		if (key->key_data_kvno < yday) {
			continue;
		}
		/* Collect the latest key */
		if ((found == NULL) || (found->key_data_kvno < key->key_data_kvno)) {
			found = key;
		}
	}
	//
	// Return the latest key found, if any
	return found;
}


/* Suggest a new kvno, following the hard-coded policy for kvno
 * format MMDDS.  The output is based on a fairly recent key,
 * if any, and it assumes that all acceptable encryption types
 * should agree.
 *
 * Return true on success, or false with errno set on failure.
 *
 * Normally, *not_before is set to 0, but it may be set higher
 * to advise waiting a while before trying.  The pressing reason
 * would be excessive use of KXOVER between two peers and the
 * corresponding rejection that a server would enforce.
 *
 * TODO: Function cleanup might be nicer with "ok" collection.
 */
bool kerberos_suggest_kvno (int32_t enctype,
				struct dercursor *crealm, struct dercursor *srealm,
				uint32_t *suggestion, time_t *not_before) {
	//
	// Normally, we would not suggest any deferral
	*not_before = 0;
	//
	// Determine the current time
	time_t now;
	if (time (&now) == (time_t) -1) {
		/* unsure if errno is already set */
		errno = EOVERFLOW;
		return false;
	}
	//
	// Construct an initial kvno suggestion based on the date alone
	struct tm scatter;
	if (gmtime_r (&now, &scatter) == NULL) {
		/* errno is set */
		return false;
	}
	uint32_t current = scatter.tm_mon * 1000 + scatter.tm_mday * 10;
	//
	// Set kx_name to "krbtgt/SERVER.REALM@CLIENT.REALM"
	krb5_principal kx_name;
	if (!_krb5_handle_error (EINVAL, krb5_build_principal_ext (
			kadm5_ctx, &kx_name,
			crealm->derlen, (char *) crealm->derptr,
			6, "krbtgt",
			srealm->derlen, (char *) srealm->derptr,
			0))) {
		goto fail_princname;
	}
	//
	// Retrieve the database entry for the current principal name
	kadm5_principal_ent_t entry = NULL;
	long query_mask = KADM5_POLICY | KADM5_KEY_DATA;
	kadm5_ret_t extension = kadm5_get_principal (
			kadm5_hdl, kx_name, entry, query_mask);
			//TODO// not &entry ?!?
	if (extension == KADM5_UNK_PRINC) {
		/* Not found, which means we can continue */
		goto success_no_extension;
	} else if (extension != 0) {
		/* Other error... bail out */
DPRINTF ("Failing kvno suggestion due to failed lookup of principal name\n");
		errno = EPERM;
		goto fail_extension;
	}
	/* The principal exists.  Is it ours? */
	if (strcmp (entry->policy, "kxover") != 0) {
		/* The policy indicates other management */
DPRINTF ("Failing kvno suggestion because the principal name falls under another policy, \"%s\"\n", entry->policy);
		errno = EACCES;
		goto fail_extension;
	}
	//
	// Find recent keys and see if they suggest changes
	krb5_key_data *recent = NULL;
	int eti;
	for (eti = 0; eti < NUM_ENCTYPES; eti++) {
		if (!enctypes [eti].crossover) {
			continue;
		}
		krb5_key_data *kd = _find_recent_key (entry, current, enctypes [eti].code);
		if (kd == NULL) {
			continue;
		}
		//TODO// Consider deferring the current attempt
		if (kd->key_data_kvno / 10 != current / 10) {
			continue;
		}
		if (kd->key_data_kvno >= current) {
			current = kd->key_data_kvno + 1;
			uint32_t fallback = (24 * 3600) >> (13 - 3 * (kd->key_data_kvno % 10) / 2);
			*not_before = now + fallback;
		}
	}
	//
	// Cleanup the entry for this principal name
success:
DPRINTF ("Returning suggested kvno = %d not before timestamp %d (now is %d)\n", current, *not_before, now);
	kadm5_free_principal_ent (kadm5_hdl, entry);
	//
	// Return the suggested kvno (and defer_seconds)
success_no_extension:
	krb5_free_principal (kadm5_ctx, kx_name);
	*suggestion = current;
	return true;
fail_extension:
	kadm5_free_principal_ent (kadm5_hdl, entry);
	krb5_free_principal (kadm5_ctx, kx_name);
fail_princname:
	return false;
}


/* Internal function to import a keyblock for realm crossover
 * from client realm crealm to service realm srealm.  The
 * keyblock is initialised with random information exported
 * from TLS and based on the keyinfo that reflects both the
 * KX-OFFER structures.
 *
 * Return true on success, or false with errno set otherwise.
 */
static bool _kxover_import_keyblock (krb5_keyblock *new_key,
			struct dercursor crealm, struct dercursor srealm,
			krb5_kvno kvno) {
	bool ok = true;
	krb5_principal kx_name;
	bool got_kx_name = false;
	//
	// Set kx_name to "krbtgt/SERVER.REALM@CLIENT.REALM"
	ok = ok && _krb5_handle_error (EINVAL, krb5_build_principal_ext (
			kadm5_ctx, &kx_name,
			crealm.derlen, (char *) crealm.derptr,
			6, "krbtgt",
			srealm.derlen, (char *) srealm.derptr,
			0));
	got_kx_name = ok;
	//
	// Find the krb5_principal and keys for kx_name
	// We may check more than just _POLICY and _KEY_DATA
	kadm5_principal_ent_t entry;
	long query_mask = KADM5_POLICY | KADM5_KEY_DATA;
	kadm5_ret_t extension = kadm5_get_principal (
			kadm5_hdl, kx_name, entry, query_mask);
			//TODO// not &entry ?!?
	if (extension == KADM5_UNK_PRINC) {
		/* Not found, we shall create from scratch */
		;
	} else if (extension != 0) {
		/* Other error... bail out */
		errno = EPERM;
		goto fail_extension;
	} else {
		/* The principal exists.  Is it ours? */
		if (strcmp (entry->policy, "kxover") != 0) {
			/* The policy indicates other management */
			errno = EACCES;
			goto fail_extension;
		}
		// Look for recent keys, covering at least the longest wait
		krb5_key_data *most_recent = _find_recent_key (entry, kvno, new_key->enctype);
		if (most_recent != NULL) {
			/* silently skip if the last key is the same as new_key;
			 * this happens when client and service use the same KDC
			 */
			if ((most_recent->key_data_length [0] == new_key->length) &&
					(memcmp (most_recent->key_data_contents [0],
					         new_key->contents,
			                         new_key->length) == 0)) {
				goto cleanup_extension;
			}
			/* serial-dependent delay: xxxx0 -> 10s, xxxx9 -> 24h
			 * this is a local policy, but currently hard-coded;
			 * it uses exponential fallback as a graceful defense
			 */
			uint32_t fallback = (24 * 3600) >> (13 - 3 * (most_recent->key_data_kvno % 10) / 2);
			krb5_timestamp first_ok = entry->mod_date + fallback;
			krb5_timestamp now;
			assert (krb5_timeofday (krb5_ctx, &now) == 0);
			if (first_ok < now) {
				/* There are too many calls, slow down */
				errno = EBUSY;
				goto fail_extension;
			}
		}
	}
	//
	// If not found yet, create the principal TODO:without key
	if (extension == KADM5_UNK_PRINC) {
		// TODO: rather not kadm5_create_principal/_3() but kadm5_setkey_principal/_3()
		// NOTE: use KADM5_KEY_DATA in mask, and set keys as desired (or do it later?)
		// NOTE: use KADM5_POLICY in mask, but not KADM5_POLICY_CLR
		// NOTE: use a NULL password -> it is just there to check
		long create_mask = (KADM5_PRINCIPAL | KADM5_POLICY);
		char *nullpw_nocheck = NULL;
		if (kadm5_create_principal (kadm5_hdl, entry, create_mask, nullpw_nocheck) != 0) {
			/* Somehow failed to create the principal */
			errno = EACCES;
			goto fail_extension;
		}
	}
	//
	// We now add the desired key; we keep any existing keys
	if (!kadm5_setkey_principal (kadm5_hdl, kx_name, new_key, 1) != 0) {
		/* Somehow failed to create the principal's new key */
		errno = EACCES;
		goto fail_extension;
	}
	//
	// Cleanup
cleanup_extension:
	if (extension == 0) {
		kadm5_free_principal_ent (kadm5_hdl, entry);
	}
	if (got_kx_name) {
		krb5_free_principal (kadm5_ctx, kx_name);
	}
	//
	// Done.  Return success or failure from ok.
	return ok;
	//
	// Failures, including cleanup.
fail_extension:
	ok = false;
	goto cleanup_extension;
}


/* Retrieve the number of random bytes for a given encryption type.
 *
 * Return true on success, or false with errno set otherwise.
 */
bool kerberos_random4key (uint32_t etype, size_t *random_len) {
	int eti;
	for (eti = 0; eti < NUM_ENCTYPES; eti++) {
		if (enctypes [eti].crossover && (etype == enctypes [eti].code)) {
			*random_len = enctypes [eti].random4key;
			return true;
		}
	}
	/* Error "not implemented" seems appropriate */
	errno = ENOSYS;
	return false;
}


/* Load the number of random bytes required for a given
 * encryption type.  This will be used when exporting key
 * material from TLS.
 *
 * Return true in case of error, false with errno otherwise.
 */
bool kerberos_random2key (uint32_t kvno, int32_t etype,
				size_t random_len, uint8_t *random_bytes,
				struct dercursor crealm, struct dercursor srealm) {
	size_t inner_keylength;
	size_t keybytes;
	int eti;
	bool ok = false;
	//
	// Find the etype entry
	for (eti = 0; eti < NUM_ENCTYPES; eti++) {
		if (enctypes [eti].crossover && (etype == enctypes [eti].code)) {
			if (enctypes [eti].deprecated) {
				fprintf (stderr, "WARNING: Deprecated encryption type in realm crossover: %s\n", enctypes [eti].name);
			}
			assert (enctypes [eti].random4key == random_len);
			ok = true;
		}
	}
	if (!ok) {
		errno = ENOENT;
		return false;
	}
	//
	// Create a key (with the desired amount of internal storage)
	ok = ok && _krb5_handle_error (EINVAL, krb5_c_keylengths (
			krb5_ctx, etype, &keybytes, &inner_keylength));
	assert (keybytes == random_len);
	krb5_keyblock *key = NULL;
	ok = ok && _krb5_handle_error (ENOMEM, krb5_init_keyblock (
			krb5_ctx, etype, inner_keylength, &key));
	//
	// Use the etype's procedure to transform random_bytes into a key
	krb5_data random_input;
	memset (&random_input, 0, sizeof (random_input));
	random_input.length = keybytes;
	random_input.data   = random_bytes;
	ok = ok && _krb5_handle_error (EINVAL, krb5_c_random_to_key (
			krb5_ctx, etype, &random_input, key));
	//
	// Now setup the key as a KXOVER key in the Kerberos key database
	ok = ok && _kxover_import_keyblock (key, crealm, srealm, kvno);
	//
	// Cleanup and success reporting
	if (key != NULL) {
		krb5_free_keyblock (krb5_ctx, key);
	}
	return ok;
}


/* Setup what is desired for the Kerberos environment.
 *
 * Since we use date/time functions and these are only standardised
 * dependently on $TZ, we shall set this variable to "UTC".
 *
 * Yeah, this is rather an amiss in the POSIX standards...
 */
bool kerberos_init (void) {
DPRINTF ("kerberos_init() called with pid=%d / ppid=%d\n", getpid (), getppid ());
	//
	// Set TZ=UTC so the POSIX time functions make /some/ sense
	char *tz_old = getenv ("TZ");
	if ((tz_old == NULL) || (strcmp (tz_old, "UTC") != 0)) {
		if (setenv ("TZ", "UTC", 1) == -1) {
DPRINTF ("Failed to set TZ=UTC in the environment\n");
			/* errno is set by setenv() */
			return false;
		}
	}
	//
	// Open a Kerberos context
	if (krb5_init_context (&krb5_ctx) != 0) {
DPRINTF ("Failed to initialise Kerberos context for basic use\n");
		return false;
	}
	//
	// Load the configuration
	const struct kerberos_config *krb5cfg = kerberos_config ();
	if (krb5cfg == NULL) {
		krb5_free_context (krb5_ctx);
		return false;
	}
	//
	// Calculate lists of encryption types
	kerberos_init_etypes (krb5cfg->crossover_enctypes);
	//
	// Open a separate Kerberos context for kadm5
	if (kadm5_init_krb5_context (&kadm5_ctx) != 0) {
DPRINTF ("Failed to initialise Kerberos context for kadm5\n");
		krb5_free_context (krb5_ctx);
		return false;
	}
	kadm5_config_params kadm5param;
	memset (&kadm5param, 0, sizeof (kadm5param));
	if (krb5cfg->kxover_realm != NULL) {
DPRINTF ("Set kxover_realm to %s\n", krb5cfg->kxover_realm);
		kadm5param.mask  |= KADM5_CONFIG_REALM;
		kadm5param.realm  = krb5cfg->kxover_realm;
	}
	//
	// Login: kadm5_init_with_skey() based on [kxover] configuration
	//TODO// This may expire and therefore need to be refreshed regularly
	char *dbargs[] = { NULL };
	if (!_krb5_handle_error (EPERM, kadm5_init_with_skey (kadm5_ctx,
				krb5cfg->kxover_name,
				krb5cfg->kxover_keytab,
				NULL /* new style GSS-API auth, old was KADM5_ADMIN_SERVICE or "kadmin/admin" */,
				&kadm5param,
				KADM5_STRUCT_VERSION, KADM5_API_VERSION_4,
				dbargs, &kadm5_hdl))) {
DPRINTF ("Failed to initialise to kadm5 service %s as %s with keytab %s\n", "(new-style,NULL)" /* OLD: KADM5_ADMIN_SERVICE or "kadmin/admin"*/, krb5cfg->kxover_name, krb5cfg->kxover_keytab);
		krb5_free_context (kadm5_ctx);
		krb5_free_context (krb5_ctx);
		return false;
	}
	//
	// Success
	return true;
}


/* Cleanup what was allocated for the Kerberos environment.
 */
bool kerberos_fini (void) {
	krb5_free_context (kadm5_ctx);
	krb5_free_context (krb5_ctx);
	return true;
}


