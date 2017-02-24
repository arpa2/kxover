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
trans_retcode_t trans_action_recv_KX_req (
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

/* Send the KX response to the KXOVER client.
 */
trans_retcode_t trans_action_send_KX_resp (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Process a failure to obtain the client's TLSA record securely.
 */
trans_retcode_t trans_action_failed_TLSA (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Implement this function
	return TRANS_FAILURE;
}

/* Send a failure response to the KXOVER client.
 */
trans_retcode_t trans_action_send_KX_failed (
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

/* Remove the shortest-living (or perhaps another, dependent on prudent policy)
 * krbtgt if we have more than we like (or allow) for any given KXOVER client.
 *
 * This can be used to implement policies such as at most two krbtgt per client,
 * which is fair when reloading is not done before half of the time has passed.
 * When 3 krbtgt exist, one can be removed.
 *
 * The reason to remove the one with the shortest life time is that there may
 * be situations where the client misses the krbtgt being replied to it, and
 * it is then likely to request another.  In this case, the previous one, the
 * one that went astray, has only a short non-overlapping life time, making it
 * the best option for removal.
 */
trans_retcode_t trans_action_remove_shortest (
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

