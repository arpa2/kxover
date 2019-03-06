/* test the tcpwrap module :-
 *
 * Send a few packages to the backend via tcpwrap.c, see them responded
 * by fakekdc, and check the result.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <signal.h>

#include "tcpwrap.h"
#include "backend.h"
#include "starttls.h"
#include "kerberos.h"
#include "socket.h"

#include <ev.h>


#if 0
void timeout_alarm (int sigalrm) {
	fprintf (stderr, "\nFinished 10 seconds of work\n");
	exit (0);
}
#endif


#if 0
void cb_second (EV_P_ ev_timer *evt, int revents) {
	printf ("Yet another second gone...\n");
}
#endif

void cb_timeout_10s (EV_P_ ev_timer *evt, int revents) {
	printf ("Shutdown after 10 seconds of presence\n");
	ev_break (EV_A_ EVBREAK_ALL);
}

void cb_please_stop (EV_P_ ev_signal *evt, int revents) {
	printf ("Stop as requested per signal\n");
	ev_break (EV_A_ EVBREAK_ALL);
}

#if 0
void cb_stdin_reading (EV_P_ ev_io *evt, int _revents) {
	char inning [1000];
	size_t inned = read (0, inning, sizeof (inning));
	printf ("cb_stdin_reading() got %d keys: %.*s\n", inned, inned, inning);
}
#endif

void cb_prepare_flush (EV_P_ ev_prepare *evp, int revents) {
	fflush (stderr);
	fflush (stdout);
}


int main (int argc, char *argv []) {

	// Process the commandline arguments
	if (argc != 6) {
		fprintf (stderr, "Usage: %s <tcpwrap-ip> <tcpwrap-port> <kdc-ip> <kdc-port> <signal>\n", argv [0]);
		exit (1);
	}

	struct sockaddr_storage sa_wrap;
	if (!socket_parse (argv [1], argv [2], (struct sockaddr *) &sa_wrap)) {
		perror ("TCP wrapper address/port failed to parse");
		exit (1);
	}

	struct sockaddr_storage sa_kdc;
	if (!socket_parse (argv [3], argv [4], (struct sockaddr *) &sa_kdc)) {
		perror ("KDC address/port failed to parse");
		exit (1);
	}

	int stop_signal = atoi (argv [5]);

	// Have a straightforward event loop (from libev)
	struct ev_loop *loop = EV_DEFAULT;

	// Ensure flushing stdout/stderr so we can count on ordering of interleaving
	ev_prepare flusher;
	ev_prepare_init (&flusher, cb_prepare_flush);
	ev_prepare_start (loop, &flusher);

	// Initialise the Kerberos module
	if (!kerberos_init ()) {
		perror ("Kerberos initialisation failed");
	}

	// Initialise the network sockets and accompanying event structures
	if (!tcpwrap_init (loop)) {
		perror ("TCP wrapper failed to initialise");
		exit (1);
	}
	if (!tcpwrap_service ((struct sockaddr *) &sa_wrap)) {
		perror ("TCP wrapper failed to service port");
		exit (1);
	}
	printf ("Listening for TCP wrappables on ('%s', %s)\n", argv [1], argv [2]);

	if (!backend_init (EV_A_ (struct sockaddr *) &sa_kdc)) {
		perror ("KDC backend failed to initialise");
		exit (1);
	}
	printf ("Listening for KDC answers from ('%s', %s)\n", argv [3], argv [4]);

	if (!starttls_init (loop)) {
		perror ("Failed to start TLS module");
		exit (1);
	}

	// Inform pypeline that we are ready for action
	printf ("--\n");
	fflush (stdout);

#if 0
	// Setup a 10s timeout alarm (which will exit on a positive note)
	struct sigaction sigact;
	sigaction (SIGALRM, NULL, &sigact);
	sigact.sa_handler = timeout_alarm;
	sigaction (SIGALRM, &sigact, NULL);
	alarm (10);
#endif

	// Setup a shutdown timer that expires after 10s
	ev_timer shutdown_timer;
	ev_timer_init (&shutdown_timer, cb_timeout_10s, 10., 0.);
	ev_timer_start (EV_A_ &shutdown_timer);

#if 0
	// Setup a repeating timer based on the event loop
	ev_timer tim;
	ev_timer_init (&tim, cb_second, 1., 1.);
	ev_timer_start (EV_A_ &tim);
#endif

#if 0
	// Test setup, see if something happens on stdin
	ev_io inkey;
	ev_io_init (&inkey, cb_stdin_reading, 0, EV_READ);
	ev_io_start (EV_A_ &inkey);
#endif

	// Register a stop signal handler
	ev_signal stop_event;
	ev_signal_init (&stop_event, cb_please_stop, stop_signal);
	ev_signal_start (EV_A_ &stop_event);

	// Run the event loop
	ev_run (EV_A_ 0);

	ev_prepare_stop (loop, &flusher);

	// Shut down the Kerberos module
	kerberos_fini ();

	exit (0);

}

