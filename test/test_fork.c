/* Test if we can actually fork() and catch that */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main (int argc, char *argv []) {
	printf ("--\n");
	fflush (stdout);
	fork ();
	exit (0);
}
