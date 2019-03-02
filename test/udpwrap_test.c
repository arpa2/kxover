/* test the udpwrap module :-
 *
 * Send a few packages to the backend via udpwrap.c, see them responded
 * by fakekdc, and check the result.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <signal.h>

#include "udpwrap.h"
#include "backend.h"
#include "socket.h"

#include <ev.h>


void timeout_alarm (int sigalrm) {
	fprintf (stderr, "\nFinished 10 seconds of work\n");
	exit (0);
}


int main (int argc, char *argv []) {

	// Process the commandline arguments
	if (argc != 5) {
		fprintf (stderr, "Usage: %s <udpwrap-ip> <udpwrap-port> <kdc-ip> <kdc-port>\n", argv [0]);
		exit (1);
	}

	struct sockaddr sa_wrap;
	if (!socket_parse (argv [1], argv [2], &sa_wrap)) {
		perror ("UDP wrapper address/port failed to parse");
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
	if (!udpwrap_init (loop, &sa_wrap)) {
		perror ("UDP wrapper failed to initialise");
		exit (1);
	}
	printf ("Listening for UDP wrappables on ('%s', %s)\n", argv [1], argv [2]);

	if (!backend_init (loop, &sa_kdc)) {
		perror ("KDC backend failed to initialise");
		exit (1);
	}
	printf ("Listening for KDC answers from ('%s', %s)\n", argv [3], argv [4]);

	// Inform pypeline that we are ready for action
	printf ("--\n");
	fflush (stdout);

	// Setup a 10s timeout alarm (which will exit on a positive note)
	struct sigaction sigact;
	sigaction (SIGALRM, NULL, &sigact);
	sigact.sa_handler = timeout_alarm;
	sigaction (SIGALRM, &sigact, NULL);
	alarm (10);

	// Run the event loop
	ev_run (loop, 0);

	exit (0);

}

