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
struct enctype { int32_t code; char *name; bool deprecated; bool crossover; size_t random4key; };
extern const struct enctype *enctypes;

struct kerberos_config {
	char *certified_client_hostname;
	char  *crossover_enctypes;
	char **crossover_enctypev;
	char *kdc_hostname;
	uint16_t kdc_port;
	//NOTYET// uint32_t kvno_offset;
	//NOTYET// char *kvno_scheme;
	//NOTYET// uint8_t kvno_maxtry;
	int crossover_lifedays;
	char *kxover_keytab;
	char *kxover_name;
	char *kxover_realm;
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
 * follow the strftime format "%Y%m%d%H%M%SZ".  The kerberos
 * implementation will not attach a NUL character at the end
 * as is the case with standard C routines.
 */
#define KERBEROS_TIME_FORMAT  "%Y%m%d%H%M%SZ"
#define KERBEROS_TIME_STRLEN  15


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
bool kerberos_time_set (time_t tstamp, dercursor out_krbtime);


/* Get a time_t value from a KerberosTime string.  The string
 * is not assumed to be NUL-terminated, but its length should
 * match the format.
 *
 * Note that TZ=UTC thanks to kerberos_init().
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_get (dercursor krbtime, time_t *out_tstamp);


/* This function is like kerberos_time_set() but it uses the
 * current wallclock time instead of a user-supplied time.
 * The tstamp value can be output, but it may be NULL if this
 * is not desired.
 *
 * Return true on success, or false with errno set on failure.
 */
bool kerberos_time_set_now (time_t *opt_out_tstamp, dercursor out_krbtime);


/* This function is like kerberos_time_get() but it adds a
 * Check that a time matches well enough with the clock time,
 * in practice meaning a window of about 5 minutes around the
 * system's idea of time.
 *
 * Return true on success, or false with errno set otherwise.
 */
bool kerberos_time_get_check_now (dercursor krbtime, time_t *out_tstamp);


/* Return a prepackaged form that can be used as SEQUENCE OF EncryptionType,
 * and included in KX-OFFER messages.  Quick DER cannot handle variable-sized
 * structures, so this must be prepared.
 *
 * The returned values are shared and must not be freed by the caller.
 */
const union dernode kerberos_seqof_enctypes (void);


/* Return the number of bytes of salt to use.  The result will not exceed
 * MAX_SALT_BYTES.
 *
 * This function does not fail.
 */
#define MAX_SALT_BYTES 32
const size_t kerberos_salt_bytes (void);


/* Retrieve the number of random bytes for a given encryption type.
 *
 * Return true on success, or false with errno set otherwise.
 */
bool kerberos_random4key (uint32_t etype, size_t *random_len);


/* Load the number of random bytes required for a given
 * encryption type.  This will be used when exporting key
 * material from TLS.
 *
 * Return true in case of error, false with errno otherwise.
 */
bool TODO_OLD_kerberos_random2key (uint32_t kvno, int32_t etype,
				size_t random_len, uint8_t *random_bytes,
				struct dercursor crealm, struct dercursor srealm);


/* The opaque type of a kerberos database connection can
 * be used for a combination of a client realm and a
 * service realm.
 * Because both client and service realm have the same
 * crossovers keys, it is necessary to choose a role
 * so that a connection can be made to the right side
 * of the realm crossover game.
 *
 * Return true on success with out_connection set, or
 * return false with errno set on failure, in which
 * case out_connection will be set to NULL.  Assume
 * that kerberos_disconnect never fails.
 */
struct kerberos_dbcnx;
//
bool kerberos_connect (struct dercursor crealm, struct dercursor srealm,
				bool as_client,
				struct kerberos_dbcnx **out_connection);
//
void kerberos_disconnect (struct kerberos_dbcnx *togo);


/* Access for reading and/or writing.  This may or may
 * not be a meaningful distinction to the underlying
 * Kerberos implementation, depending on its idea of
 * access control.  Later operations may therefore
 * fail to write, even if write access was granted.
 *
 * This usually causes login to the local key store.
 * Login may involve network traffic, like a GSS-API
 * exchange, so we desire a callback when it is done.
 * This call may be made from another thread!
 *
 * The login may take some time, up to seconds even.
 * For this reason, the best use of this call is to
 * invoke it as soon as the two realms and the local
 * role (client or service realm) are known.  The
 * idea is that the KXOVER progress can then happen
 * in parallel with the Kerberos access setup.
 *
 * Return true on success, or false with errno on failure.
 *
 * The callback function is called with last_errno set
 * to 0 on success, or an error number otherwise.
 */
typedef void (*kerberos_access_callback) (
				struct kerberos_dbcnx *cnx,
				void *cbdata,
				int last_errno);
//
bool kerberos_access (struct kerberos_dbcnx *cnx,
				bool as_writer,
				kerberos_access_callback cb,
				void *cbdata);


/* Iterate over realm crossover keys.  Start without an
 * entry, then call for the next entry to get the first,
 * second and so on.  Data for the iterator is stored
 * in the kerberos_dbcnx type and will be cleaned up
 * during kerberos_disconnect().
 *
 * _reset() might report an error due to technical reasons
 *          other than not finding a key;
 * _next() reports a false result when no more keys are
 *         available, which may be the case with the first
 *         invocation (when no keys exist yet).
 *
 * Return true on succes, or false with errno on failure;
 * only when nothing is found during _next() will errno
 * be deliberately set to 0 for OK.
 */
bool kerberos_iter_reset (struct kerberos_dbcnx *cnx);
bool kerberos_iter_next  (struct kerberos_dbcnx *cnx,
				uint32_t *out_kvno,
				int32_t *out_etype);


/* Remove the given key from the key store under the
 * current kerberos_dbcnx connection.  It is not
 * generally safe to remove keys while iteration is
 * in progress; as an exception, it is safe to delete
 * the key reported last by kerberos_iter_next().
 */
bool kerberos_del_key (struct kerberos_dbcnx *cnx,
				uint32_t kvno, int32_t etype);


/* Load the number of random bytes required for a given
 * encryption type.  This will be used when exporting key
 * material from TLS.
 *
 * On some Kerberos systems, when the same KDC hosts both
 * the client and service realm, there could be an error
 * caused by the addition of the same key.  The implementation
 * should in that case recognise that the key proposed for
 * addition already exists, with the exact same data, and
 * silently ignore the addition request.
 *
 * Return true in case of error, false with errno otherwise.
 */
bool kerberos_add_key (struct kerberos_dbcnx *cnx,
				uint32_t kvno, int32_t etype,
				size_t random_len, uint8_t *random_bytes);


/* Setup what is desired for the Kerberos environment.
 * You should call this before any kerberos_connect().
 */
bool kerberos_init (void);


/* Cleanup what was allocated for the Kerberos environment.
 * You should call any kerberos_disconnect() before this.
 */
bool kerberos_fini (void);


#endif /* KXOVER_KERBEROS_H */
