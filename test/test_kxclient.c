/* simple-client -- Run a client for a client and service realm.
 *
 * This is a simple wrapper around the kxover_client() call
 * that creates the infrastructure needed and then calls the
 * function.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "backend.h"
#include "socket.h"
#include "kxover.h"

#include <ev.h>

#include <quick-der/api.h>



void cb_timeout_10s (EV_P_ ev_timer *evt, int revents) {
	printf ("Timeout after 10 seconds of patience\n");
	exit (1);
}

#if 0
void cb_please_stop (EV_P_ ev_signal *evt, int revents) {
	printf ("Stop as requested per signal\n");
	ev_break (EV_A_ EVBREAK_ALL);
}
#endif

void cb_kxover_done (void *cbdata, int result_errno,
			struct dercursor client_realm,
			struct dercursor service_realm) {
printf ("cb_kxover_done() called with errno == %d (%s)\n", result_errno, strerror (result_errno));
	if (result_errno != 0) {
		fprintf (stderr, "KXOVER client failed: %s", strerror (result_errno));
		exit (1);
	}
printf ("cb_kxover_done() returns\n");
}


int main (int argc, char *argv []) {

	// Process the commandline arguments
	if (argc != 7) {
		fprintf (stderr, "Usage: %s <client-realm> <service-realm> <kdc-ip> <kdc-port> <dnssec-rootkey-file> <etc-hosts-file>\n", argv [0]);
		exit (1);
	}

	dercursor crealm;
	crealm.derptr =         argv [1] ;
	crealm.derlen = strlen (argv [1]);
	dercursor srealm;
	srealm.derptr =         argv [2] ;
	srealm.derlen = strlen (argv [2]);

#if 0
	struct sockaddr sa_wrap;
	if (!socket_parse (argv [1-TAKEN], argv [2-TAKEN], &sa_wrap)) {
		perror ("TCP wrapper address/port failed to parse");
		exit (1);
	}
#endif

	struct sockaddr sa_kdc;
	if (!socket_parse (argv [3], argv [4], &sa_kdc)) {
		perror ("KDC address/port failed to parse");
		exit (1);
	}

#if 0
	int stop_signal = atoi (argv [5-TAKEN]);
#endif

	char *dnssec_rootkey_file = argv [5];

	char *etc_hosts_file = argv [6];

	// Have a straightforward event loop (from libev)
	struct ev_loop *loop = EV_DEFAULT;

	// Initialise the network sockets and accompanying event structures
#if 0
	if (!udpwrap_init (loop, &sa_wrap)) {
		perror ("UDP wrapper failed to initialise");
		exit (1);
	}
	printf ("Listening for UDP wrappables on ('%s', %s)\n", argv [1-TAKEN], argv [2-TAKEN]);
#endif

printf ("backup_init()...\n");
	if (!backend_init (loop, &sa_kdc)) {
		perror ("KDC backend failed to initialise");
		exit (1);
	}
	printf ("Listening for KDC answers from ('%s', %s)\n", argv [3], argv [4]);

printf ("kxover_init ()...\n");
	kxover_init (EV_A_ dnssec_rootkey_file, etc_hosts_file);

	// Inform pypeline that we are ready for action
printf ("pypeline detachment...\n");
	printf ("--\n");
	fflush (stdout);

	// Setup a shutdown timer that expires after 10s
	ev_timer shutdown_timer;
	ev_timer_init (&shutdown_timer, cb_timeout_10s, 10., 0.);
	ev_timer_start (EV_A_ &shutdown_timer);

#if 0
	// Register a stop signal handler
	ev_signal stop_event;
	ev_signal_init (&stop_event, cb_please_stop, stop_signal);
	ev_signal_start (EV_A_ &stop_event);
#endif

	// Start the KXOVER client
	struct kxover_data *client_handle;
printf ("kxover_client() starts now\n");
	client_handle = kxover_client (cb_kxover_done, "cbdata", crealm, srealm);
	if (!client_handle) {
		perror ("Failed to start kxover_client");
		exit (1);
	}

	// Run the event loop
	ev_run (EV_A_ 0);

	exit (0);

}

