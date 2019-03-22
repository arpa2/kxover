/* kxover client tool -- interact with realm crossover keys
 *
 * Inasfar as they are under the "kxover" policy, this tool can
 * iterate over keys to list, add or remove them.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <getopt.h>
#include <time.h>

#include <com_err.h>
#include <errortable.h>

#include "kerberos.h"



/* Print basic usage information */
void usage (char *progname) {
	//TODO// fprintf (stderr, "Usage: %s <cmd> [[krbtgt/][SREALM]@[CREALM]]\n"
	fprintf (stderr, "Usage: %s <cmd> SREALM [CREALM]\n"
			"<cmd> is one of:\n"
			"  list -> iterate over crossover keys\n"
			"  add  -> insert a new crossover key\n"
			"  del  -> remove given crossover key\n", progname);
	//TODO// work on the client or server KDC?
	//TODO// select etype and/or kvno
	//TODO// authentication identity?
}


/* Callback that stores kxerrno and continues the main thread */
volatile bool got_kxerrno = false;
void cb_set_kxerrno (struct kerberos_dbcnx *dbcnx, void *cbdata, int last_errno) {
	kxerr_t *pkxerrno = cbdata;
	fprintf (stderr, "DEBUG: Callback reports last_errno=%d\n", last_errno);
	*pkxerrno = last_errno;
	got_kxerrno = true;
}


/* list SREALM [CREALM] */
bool cmd_list (bool as_client, char *srealm, char *crealm) {
	struct kerberos_dbcnx *dbcnx = NULL;
	//
	// Consistency checks
	assert (srealm != NULL);
	if (crealm == NULL) {
		fprintf (stderr, "No support for iteration over all crossover keys in a realm yet\n");
		kxerrno = ENOSYS;
		goto fail;
	}
	//
	// Connect to the key database and login
	struct dercursor crealm_der;
	struct dercursor srealm_der;
	crealm_der.derptr = crealm;
	srealm_der.derptr = srealm;
	crealm_der.derlen = strlen ((crealm != NULL) ? crealm : "");
	srealm_der.derlen = strlen ((srealm != NULL) ? srealm : "");
	if (!kerberos_connect (crealm_der, srealm_der, as_client, &dbcnx)) {
		goto disconnect_fail;
	}
	if (!kerberos_access (dbcnx, false, cb_set_kxerrno, &kxerrno)) {
		kxerrno = EACCES;
		com_err (__FILE__, kxerrno, "Access could not start");
		goto disconnect_fail;
	}
	//TODO// Proper sync please :) but we don't need it before threading
	while (!got_kxerrno) {
		sleep (1);
	}
	if (kxerrno != 0) {
		com_err (__FILE__, kxerrno, "Access denied");
		goto disconnect_fail;
	}
	//
	// Iterate over the kvno and etypes
	printf ("Iterating crossover keys from clients in %s to services in %s\n", crealm, srealm);
	if (!kerberos_iter_reset (dbcnx)) {
		com_err (__FILE__, kxerrno, "Could not iterate keys");
		goto disconnect_fail;
	}
	uint32_t kvno;
	int32_t enctype;
	int ctr = 0;
	while (kerberos_iter_next (dbcnx, &kvno, &enctype)) {
		printf ("Found a key: kvno=%d, enctype=%d\n", kvno, enctype);
		ctr++;
	}
	if (kxerrno != 0) {
		com_err (__FILE__, kxerrno, "Key iteration terminated");
		goto disconnect_fail;
	}
	printf ("Found %d keys for krbtgt/%s@%s\n", ctr, srealm, crealm);
	kerberos_disconnect (dbcnx);
	return true;
disconnect_fail:
	kerberos_disconnect (dbcnx);
fail:
	return false;
}


/* add SREALM [CREALM] */
bool cmd_add (bool as_client, char *srealm, char *crealm) {
	assert (srealm != NULL);
	//TODO// We need even more logic than this...
	kxerrno = ENOSYS;
	return false;
}


/* del SREALM [CREALM] */
bool cmd_del (bool as_client, char *srealm, char *crealm) {
	assert (srealm != NULL);
	//TODO// We need even more logic than this...
	kxerrno = ENOSYS;
	return false;
}


/* main programs define the kxerrno variable */
kxerr_t kxerrno = 0;


/* kxover-client tool main() program */
int main (int argc, char *argv []) {
	bool ok = true;
	bool need_help = false;
	bool got_krb5 = false;
	//
	// Preliminary checking
	if ((argc < 3) || (argc > 4)) {
		kxerrno = EINVAL;
		ok = false;
	}
	char *prognm = (argc > 0) ? argv [0] : "kxover-client";
	char *cmd    = (argc > 1) ? argv [1] : NULL;
	char *srealm = (argc > 2) ? argv [2] : NULL;
	char *crealm = (argc > 3) ? argv [3] : NULL;
	if (ok) {
		if (kerberos_init ()) {
			got_krb5 = true;
		} else {
			com_err (__FILE__, kxerrno, "Failed to initialise Kerberos");
			ok = false;
		}
	}
	//
	// Determine whether we are acting as a client or server
	bool as_client = false;
	//
	// Invoke subcommand or decide on errors */
	if (!ok) {
		need_help = true;
	} else if (strcmp (cmd, "list") == 0) {
		ok = cmd_list (as_client, srealm, crealm);
	} else if (strcmp (cmd, "add") == 0) {
		ok = cmd_add  (as_client, srealm, crealm);
	} else if (strcmp (cmd, "del") == 0) {
		ok = cmd_del  (as_client, srealm, crealm);
	} else {
		fprintf (stderr, "Invalid subcommand: %s\n", cmd);
		kxerrno = ENOSYS;
		ok = false;
		need_help = true;
	}
	//
	// Close down and possibly report errors
	if (got_krb5) {
		kerberos_fini ();
	}
	if (!ok) {
		fprintf (stderr, "Error in %s: %s\n", prognm, error_message (kxerrno));
	}
	if (need_help) {
		usage (prognm);
	}
	exit (ok ? 0 : 1);
}


