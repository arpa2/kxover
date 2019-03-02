/* test the udpwrap module :-
 *
 * Send a few packages to the backend via udpwrap.c, see them responded
 * by fakekdc, and check the result.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>

#include <sys/wait.h>

#include <ev.h>


int main (int argc, char *argv []) {
	struct ev_loop *loop = EV_DEFAULT;

	ev_run (loop, 0);

	exit (0);
}

