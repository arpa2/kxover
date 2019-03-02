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

void cb_exit_0 (EV_P_ ev_timer *evt, int revents) {
	printf ("Shutdown after 10 seconds of presence\n");
	exit (0);
}

#if 0
void cb_stdin_reading (struct ev_loop *loop, ev_io *evt, int _revents) {
	char inning [1000];
	size_t inned = read (0, inning, sizeof (inning));
	printf ("cb_stdin_reading() got %d keys: %.*s\n", inned, inned, inning);
}
#endif


int main (int argc, char *argv []) {

	// Process the commandline arguments
	if (argc != 5) {
		fprintf (stderr, "Usage: %s <tcpwrap-ip> <tcpwrap-port> <kdc-ip> <kdc-port>\n", argv [0]);
		exit (1);
	}

	struct sockaddr sa_wrap;
	if (!socket_parse (argv [1], argv [2], &sa_wrap)) {
		perror ("TCP wrapper address/port failed to parse");
		exit (1);
	}

	struct sockaddr sa_kdc;
	if (!socket_parse (argv [3], argv [4], &sa_kdc)) {
		perror ("KDC address/port failed to parse");
		exit (1);
	}

	// Have a straightforward event loop (from libev)
	struct ev_loop *loop = EV_DEFAULT;

	// Initialise the network sockets and accompanying event structures
	if (!tcpwrap_init (loop)) {
		perror ("TCP wrapper failed to initialise");
		exit (1);
	}
	if (!tcpwrap_service (&sa_wrap)) {
		perror ("TCP wrapper failed to service port");
		exit (1);
	}
	printf ("Listening for TCP wrappables on ('%s', %s)\n", argv [1], argv [2]);

	if (!backend_init (loop, &sa_kdc)) {
		perror ("KDC backend failed to initialise");
		exit (1);
	}
	printf ("Listening for KDC answers from ('%s', %s)\n", argv [3], argv [4]);

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

	// Setup a shuftdown timer that expires after 10s
	ev_timer shutdown_timer;
	ev_timer_init (&shutdown_timer, cb_exit_0, 10., 0.);
	ev_timer_start (loop, &shutdown_timer);

#if 0
	// Setup a repeating timer based on the event loop
	ev_timer tim;
	ev_timer_init (&tim, cb_second, 1., 1.);
	ev_timer_start (loop, &tim);
#endif

#if 0
	// Test setup, see if something happens on stdin
	ev_io inkey;
	ev_io_init (&inkey, cb_stdin_reading, 0, EV_READ);
	ev_io_start (loop, &inkey);
#endif

	// Run the event loop
	ev_run (loop, 0);

	exit (0);

}

