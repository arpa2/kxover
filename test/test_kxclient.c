/* test_kxclient -- Run a client for a client and service realm.
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
#include <time.h>

#include "socket.h"
#include "kxover.h"
#include "starttls.h"
#include "kerberos.h"

#include <ev.h>

#include <quick-der/api.h>


// Have a straightforward event loop (from libev)
struct ev_loop *loop;
int sys_exit = 0;



void cb_timeout_15s (EV_P_ ev_timer *evt, int revents) {
	printf ("Timeout after 15 seconds of patience\n");
	sys_exit = 1;
	ev_break (EV_A_ EVBREAK_ONE);
}

#if 0
void cb_please_stop (EV_P_ ev_signal *evt, int revents) {
	printf ("Stop as requested per signal\n");
	ev_break (EV_A_ EVBREAK_ONE);
}
#endif

void cb_kxover_done (void *cbdata, int result_errno,
			struct dercursor client_realm,
			struct dercursor service_realm) {
	fprintf (stderr, "KXOVER finished for krbtgt/%.*s@%.*s\n", service_realm.derlen, service_realm.derptr, client_realm.derlen, client_realm.derptr);
	if (result_errno != 0) {
		fprintf (stderr, "KXOVER client failed: %d (%s)\n", result_errno, strerror (result_errno));
		sys_exit = 1;
		ev_break (EV_A_ EVBREAK_ONE);
		return;
	}
}


void cb_prepare_flush (EV_P_ ev_prepare *evp, int revents) {
	fflush (stderr);
	fflush (stdout);
}


int main (int argc, char *argv []) {

	static int c_main = 0; assert (c_main++ == 0);

	// Process the commandline arguments
	if (argc != 5) {
		fprintf (stderr, "Usage: %s <client-realm> <service-realm> <dnssec-rootkey-file> <etc-hosts-file>\n", argv [0]);
		exit (1);
	}

	dercursor crealm;
	crealm.derptr =         argv [1] ;
	crealm.derlen = strlen (argv [1]);
	dercursor srealm;
	srealm.derptr =         argv [2] ;
	srealm.derlen = strlen (argv [2]);

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

	char *dnssec_rootkey_file = argv [3];

	char *etc_hosts_file = argv [4];

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

	// Ensure flushing stdout/stderr so we can count on ordering of interleaving
	ev_prepare flusher;
	ev_prepare_init (&flusher, cb_prepare_flush);
	ev_prepare_start (loop, &flusher);
	static int c_flusher_init = 0; assert (c_flusher_init++ == 0);

	// Initialise the Kerberos module
printf ("kerberos_init ()...\n");
	if (!kerberos_init ()) {
		perror ("Kerberos initialisation failed");
	}
	static int c_k5init = 0; assert (c_k5init++ == 0);

printf ("starttls_init () -> faketls_init ()...\n");
	starttls_init (loop);
	static int c_tlsinit = 0; assert (c_tlsinit++ == 0);

printf ("kxover_init ()...\n");
	kxover_init (EV_A_ dnssec_rootkey_file, etc_hosts_file);
	static int c_kxinit = 0; assert (c_kxinit++ == 0);

	// Setup a shutdown timer that expires after 15s
	ev_timer shutdown_timer;
	ev_timer_init (&shutdown_timer, cb_timeout_15s, 15., 0.);
	ev_timer_start (EV_A_ &shutdown_timer);
	static int c_shut = 0; assert (c_shut++ == 0);

#if 0
	// Register a stop signal handler
	ev_signal stop_event;
	ev_signal_init (&stop_event, cb_please_stop, stop_signal);
	ev_signal_start (EV_A_ &stop_event);
#endif

	// Inform pypeline that we are ready for action
printf ("pypeline detachment...\n");
	printf ("--\n");
	fflush (stdout);
	static int c_detach = 0; assert (c_detach++ == 0);

	// Start the KXOVER client
	struct kxover_data *client_handle;
printf ("kxover_client() starts now, for pid = %d, ppid = %d, at %d\n", getpid (), getppid (), time (NULL));
	static int c_kxcli = 0; assert (c_kxcli++ == 0);
	client_handle = kxover_client (cb_kxover_done, "cbdata", crealm, srealm);
	if (!client_handle) {
		perror ("Failed to start kxover_client");
		sys_exit = 1;
	}

	// Run the event loop
	if (sys_exit == 0) {
		ev_run (EV_A_ 0);
	}

	ev_prepare_stop (loop, &flusher);

printf ("kxover_fini ()...\n");
	kxover_fini ();

	// Shut down the Kerberos module
printf ("kerberos_fini ()...\n");
	kerberos_fini ();

printf ("exit (%d)\n", sys_exit);
	exit (sys_exit);

}

