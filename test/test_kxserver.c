/* test_kxserver -- Run a server for a given service realm.
 *
 * This is a simple wrapper around the kxover_server() call
 * that creates the infrastructure needed and then calls the
 * function for client connections.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "socket.h"
#include "kxover.h"
#include "starttls.h"
#include "kerberos.h"

#include <ev.h>

#include <quick-der/api.h>


// Have a straightforward event loop (from libev)
struct ev_loop *loop;
int sys_exit = 0;



void cb_timeout_10s (EV_P_ ev_timer *evt, int revents) {
	printf ("Timeout after 10 seconds of patience\n");
	sys_exit = 1;
	ev_break (EV_A_ EVBREAK_ALL);
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
	fprintf (stderr, "KXOVER finished for krbtgt/%.*s@%.*s\n", service_realm.derlen, service_realm.derptr, client_realm.derlen, client_realm.derptr);
	if (result_errno != 0) {
		fprintf (stderr, "KXOVER server failed: %d (%s)\n", result_errno, strerror (result_errno));
		sys_exit = 1;
		ev_break (EV_A_ EVBREAK_ALL);
		return;
	}
printf ("cb_kxover_done() returns\n");
}


int main (int argc, char *argv []) {

	// Process the commandline arguments
	if (argc != 4) {
		fprintf (stderr, "Usage: %s <service-realm> <dnssec-rootkey-file> <etc-hosts-file>\n", argv [0]);
		exit (1);
	}

	dercursor srealm;
	srealm.derptr =         argv [1] ;
	srealm.derlen = strlen (argv [1]);

#if 0
	struct sockaddr_storage sa_wrap;
	if (!socket_parse (argv [1-TAKEN], argv [2-TAKEN], &sa_wrap)) {
		perror ("TCP wrapper address/port failed to parse");
		exit (1);
	}
#endif

#if 0
	int stop_signal = atoi (argv [5-TAKEN]);
#endif

	char *dnssec_rootkey_file = argv [2];

	char *etc_hosts_file = argv [3];

	// Initialise the network sockets and accompanying event structures
#if 0
	if (!udpwrap_init (loop, &sa_wrap)) {
		perror ("UDP wrapper failed to initialise");
		exit (1);
	}
	printf ("Listening for UDP wrappables on ('%s', %s)\n", argv [1-TAKEN], argv [2-TAKEN]);
#endif

	// Use the default loop, plain and simple
	loop = EV_DEFAULT;

	// Initialise the Kerberos module
printf ("kerberos_init ()...\n");
	if (!kerberos_init ()) {
		perror ("Kerberos initialisation failed");
	}

printf ("starttls_init () -> faketls_init ()...\n");
	starttls_init (loop);

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

	// Run the KXOVER server
	fprintf (stderr, "TODO: This program is incomplete; we can also call from tcpwrap.c\n");
	exit (1);
	struct kxover_data *server_handle;
	struct dercursor reqmsg = { .derptr = NULL, .derlen = 0 };
	int sox = -1;
	server_handle = kxover_server (cb_kxover_done, "cbdata", reqmsg, sox);
	if (!server_handle) {
		perror ("Failed to start kxover_server");
		sys_exit = 1;
	}

	// Run the event loop
	if (sys_exit == 0) {
		ev_run (EV_A_ 0);
	}

printf ("kxover_fini ()...\n");
	kxover_fini ();

	// Shut down the Kerberos module
printf ("kerberos_fini ()...\n");
	kerberos_fini ();

printf ("exit (%d)\n", sys_exit);
	exit (sys_exit);

}

