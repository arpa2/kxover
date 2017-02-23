/* server.c -- Common plugin routines, used in the KXOVER server.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <perpetuum/model.h>

#include "kxover_server.h"


int main (int argc, char *argv []) {
	//TODO// Implement, elsewhere
}


/* The initial transition for this workflow indicates that a KXOVER client
 * wants to go through a KXOVER exchange.  This is strictly event-driven.
 */
trans_retcode_t trans_action_receive_KX_request (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata ) {
	if (opt_evdata == NULL) {
		/* Wait for the event to occur, but hold off the scheduler */
		return TRANS_MAXDELAY;
	}
	//TODO// Implement this function
	return TRANS_FAILURE;
}


/* Store the produced krbtgt in kdb, so we can process future client requests.
 */
trans_retcode_t trans_action_store_krbtgt (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Generate a response to send to the KXOVER client.
 */
trans_retcode_t trans_action_generate_response (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Send the KX response to the KXOVER client.
 */
trans_retcode_t trans_action_send_KX_response (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process a failure to obtain the client's SRV record securely.
 */
trans_retcode_t trans_action_failed_krb_SRV (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process a failure to obtain the client's TLSA record securely.
 */
trans_retcode_t trans_action_failed_kdc_TLSA (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Send a failure response to the KXOVER client.
 */
trans_retcode_t trans_action_respond_failed (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Expire one krbtgt for the given KXOVER client.
 */
trans_retcode_t trans_action_expiration_timer (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Remove the oldest (or perhaps another, dependent on prudent policy) krbtgt
 * if we have more than we like (or allow) for any given KXOVER client.
 */
trans_retcode_t trans_action_remove_oldest (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Expire a negative result from the cache, so as to re-enable interactions
 * with the KXOVER client.
 */
trans_retcode_t trans_action_cache_exp_timer (
			PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

