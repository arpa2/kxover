/* server.c -- Common plugin routines, used in the KXOVER client.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <perpetuum/model.h>

#include "kxover_client.h"


int main (int argc, char *argv []) {
	//TODO// Implement, elsewhere
}


/* This is the initiating transition; it is triggered only by events.
 */
trans_retcode_t trans_action_krbtgtMissing (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	if (opt_evdata == NULL) {
		/* Be open to events, but fend off the scheduler */
		return TRANS_MAXDELAY;
	}
	//TODO// Implement the event handler
	return TRANS_FAILURE;
}

/* Process a failed KX request sent to the KXOVER server.
 */
trans_retcode_t trans_action_failed_KX (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process the reception of a KX response from the KXOVER server.
 */
trans_retcode_t trans_action_got_KX_resp (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata ) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Now we have a krbtgt, send a notification to any requesters that may be
 * waiting for it.
 */
trans_retcode_t trans_action_send_krbtgt_to_all_requesters (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process a timer of a krbtgt's initial usage period; if it is referenced
 * again between now and its expiration, then make sure to refresh it.
 */
trans_retcode_t trans_action_krbtgt_refresh_timer (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Given a krbtgt in both the fresh and dawn places, remove the one in dawn.
 */
trans_retcode_t trans_action_krbtgt_remove_dawn (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_SUCCESS;
}

/* Remove an expired krbtgt from kdb.
 */
trans_retcode_t trans_action_krbtgt_expired_remove (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Send a KX request to the KXOVER server.
 */
trans_retcode_t trans_action_send_KX_req (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* We have a krbtgt in dawn, meaning we would like to deliver it but also
 * initiate its refreshment by initiating an SRV request and so on.
 */
trans_retcode_t trans_action_have_dawn_krbtgt (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* We have a fresh krbtgt and can simply pass it on to the KDC.
 */
trans_retcode_t trans_action_have_fresh_krbtgt (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	return TRANS_SUCCESS;
}

/* Synchronise after succeeding with DANE but failing with KX.
 */
trans_retcode_t trans_action_DANEwoKX (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	return TRANS_SUCCESS;
}

/* Synchronise after success with KX but failure with DANE.
 */
trans_retcode_t trans_action_KXwoDANE (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	return TRANS_SUCCESS;
}

/* Synchronise after both the KX and DANE branch failed.
 */
trans_retcode_t trans_action_neither (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	return TRANS_SUCCESS;
}

/* A silent transition to a state where we will look for an SRV record.
 */
trans_retcode_t trans_action_need_SRV (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	return TRANS_SUCCESS;
}

/* Request A and/or AAAA records.
 */
trans_retcode_t trans_action_dns_req_A_AAAA (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process the failure to find either A or AAAA record.
 */
trans_retcode_t trans_action_failed_A_AAAA (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process a successful response with A and/or AAAA records.
 */
trans_retcode_t trans_action_got_A_AAAA (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process a failure of a TLSA request.
 */
trans_retcode_t trans_action_failed_TLSA (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process a failure and cache the negative outcome for a short while.
 */
trans_retcode_t trans_action_failedStop (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	return TRANS_SUCCESS;
}

/* Fire after the expiration of the negative cache timer.
 */
trans_retcode_t trans_action_cache_exp_timer (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

