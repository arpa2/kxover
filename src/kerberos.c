/* Kerberos interactions.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include "kerberos.h"



/* Lookup the local KDC hostname for a given realm.
 *
 * Return an empty string if none is known.
 */
const struct dercursor kerberos_localrealm2hostname (struct dercursor local_realm) {
	struct dercursor retval = { .derptr="localhost", .derlen=9 };
	return retval;
}


