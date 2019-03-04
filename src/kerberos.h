/* Kerberos interactions.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef KXOVER_KERBEROS_H
#define KXOVER_KERBEROS_H


#include <quick-der/api.h>


/* Lookup the local KDC hostname for a given realm.
 *
 * Return an empty string if none is known.
 */
const struct dercursor kerberos_localrealm2hostname (struct dercursor local_realm);


#endif /* KXOVER_KERBEROS_H */
