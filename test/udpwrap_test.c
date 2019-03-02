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


int main (int argc, char *argv []) {
	system ("./fakekdc   88 bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der &");
	system ("./udpclient 88 bin/krb5-as-req1.der bin/krb5-as-rep1.der bin/krb5-as-req2.der bin/krb5-as-rep2.der &");
	pid_t pw1, pw2;
	int st1, st2;
	pw1 = wait (&st1);
	pw2 = wait (&st2);
	printf ("States returned are: %d -> %d and %d -> %d\n", pw1, st1, pw2, st2);
}
