/* Kerberos interactions.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef KXOVER_KERBEROS_H
#define KXOVER_KERBEROS_H


#include <quick-der/api.h>


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
struct enctype { int32_t code; char *name; bool deprecated; bool crossover; };
extern const struct enctype *enctypes;

struct kerberos_config {
	char *cerfified_client_hostname;
	char **crossover_enctypes;
	char *kdc_hostname;
	uint16_t kdc_port;
	uint32_t kvno_offset;
	char *kvno_scheme;
	uint8_t kvno_maxtry;
	uint8_t crossover_lifedays;
};


/* Load the configuration.
 */
const struct kerberos_config *kerberos_config (void);


/* Use Kerberos to generate pseudo-random bytes.
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_prng (uint8_t *outptr, uint16_t outlen);


/* Install a new krbgtgt/SERVICE.REALM@CLIENT.REALM with the given key.
 *
 * Return true on success, or false with errno set on failure.
 */
bool install_crossover_key (int TODO);


/* Lookup the local KDC hostname for a given realm.
 *
 * Return an empty string if none is known.
 */
const struct dercursor kerberos_localrealm2hostname (struct dercursor local_realm);


/* KerberosTime strings have a fixed length of 15 chars, and
 * follow the strftime format "%Y%m%d%H%M%SZ".  In our code,
 * we always attach a NUL character (making the size 16 chars)
 * so we can use the standard C routines.  This extra NUL is
 * not sent or received in the DER encoding, of course.
 */
#define KERBEROS_TIME_FORMAT  "%Y%m%d%H%M%SZ"
#define KERBEROS_TIME_STRLEN  15
#define KERBEROS_TIME_STORAGE 16

typedef char kerberos_time_t [KERBEROS_TIME_STORAGE];


/* Set a KerberosTime from a time_t value.  The output string
 * will be NUL terminated, but its string length will always
 * be the fixed value KERBEROS_TIME_STRLEN.
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_set (time_t tstamp, char out_krbtime [KERBEROS_TIME_STORAGE]);


/* Get a time_t value from a KerberosTime string.  The string
 * is assumed to be NUL-terminated, even if its length is
 * fixed and predictable.
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_get (const char krbtime [KERBEROS_TIME_STORAGE], time_t *out_tstamp);


/* Return a prepackaged form that can be used as SEQUENCE OF EncryptionType,
 * and included in KX-OFFER messages.  Quick DER cannot handle variable-sized
 * structures, so this must be prepared.
 *
 * The returned values are shared and must not be freed by the caller.
 */
const union dernode kerberos_seqof_enctypes (void);


/* Setup what is desired for the Kerberos environment.
 */
bool kerberos_init (void);


/* CLeanup what was allocated for the Kerberos environment.
 */
bool kerberos_fini (void);


#endif /* KXOVER_KERBEROS_H */
