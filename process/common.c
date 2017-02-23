/* common.c -- Common plugin routines, used in the KXOVER client and server.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <perpetuum/model.h>

/* We include the kxover_client and kxover_server processes to profit from
 * type checking the transition function names.  But there are overlapping
 * symbols, and we should undefine those to avoid reports on redefinitions
 * with possibly different values -- and we don't use those anyway.
 */

#include "kxover_client.h"
#undef TRANS_INDEX_cache_exp_timer
#undef TRANS_INDEX_signature_error
#undef TRANS_INDEX_got_krb_SRV
#undef TRANS_INDEX_dnssec_req_krb_SRV
#undef TRANS_INDEX_got_kdc_TLSA
#undef TRANS_INDEX_signature_good
#undef TRANS_INDEX_failed_krb_SRV
#undef TRANS_INDEX_successfulEnd
#undef TRANS_INIT_cache_exp_timer
#undef TRANS_INIT_signature_error
#undef TRANS_INIT_signature_good

#include "kxover_server.h"
#undef TRANS_INDEX_cache_exp_timer
#undef TRANS_INDEX_signature_error
#undef TRANS_INDEX_got_krb_SRV
#undef TRANS_INDEX_dnssec_req_krb_SRV
#undef TRANS_INDEX_got_kdc_TLSA
#undef TRANS_INDEX_signature_good
#undef TRANS_INDEX_failed_krb_SRV
#undef TRANS_INDEX_successfulEnd
#undef TRANS_INIT_cache_exp_timer
#undef TRANS_INIT_signature_error
#undef TRANS_INIT_signature_good


/* This is an elementary request-sending transition, in this case to request
 * a _kerberos TXT record for a server hostname with DNSSEC protection.
 */
trans_retcode_t trans_action_dnssec_req_krb_TXT (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Request TXT record with DNSSEC assurance, report TRANS_SUCCESS
	return TRANS_FAILURE;
}

/* This is an event-handling transition, reporting on successful reception
 * of a _kerberos TXT record for a server hostname with DNSSEC protection.
 */
trans_retcode_t trans_action_got_krb_TXT (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	if (opt_evdata == NULL) {
		/* Put off the scheduler, and wait for the event to arrive */
		return TRANS_MAXDELAY;
	}
	//TODO// Process event input
	return TRANS_FAILURE;
}

/* This is an elementary request-sending transition, in this case to request
 * an SRV record for the KDC with DNSSEC protection.
 */
trans_retcode_t trans_action_dnssec_req_krb_SRV (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Request SRV record with DNSSEC assurance, report TRANS_SUCCESS
	return TRANS_FAILURE;
}

/* This is an event-handling transition, reporting on successful reception
 * of an SRV record for the KDC with DNSSEC protection.
 */
trans_retcode_t trans_action_got_krb_SRV (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	if (opt_evdata == NULL) {
		/* Put off the scheduler, and wait for the event to arrive */
		return TRANS_MAXDELAY;
	}
	//TODO// Process event input
	return TRANS_FAILURE;
}

/* This is an elementary request-sending transition, in this case to request
 * a TLSA record for the KDC's SRV information with DNSSEC protection.
 */
trans_retcode_t trans_action_dnssec_req_kdc_TLSA (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Request TLSA record with DNSSEC assurance, report TRANS_SUCCESS
	return TRANS_FAILURE;
}

/* This is an event-handling transition, reporting on successful reception
 * of a TLSA record for the KDC's SRV information with DNSSEC protection.
 */
trans_retcode_t trans_action_got_kdc_TLSA (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	if (opt_evdata == NULL) {
		/* Put off the scheduler, and wait for the event to arrive */
		return TRANS_MAXDELAY;
	}
	//TODO// Process event input
	return TRANS_FAILURE;
}

/* Report success in signature validation.  This has an alternative to the
 * trans_action_signature_error.
 */
trans_retcode_t trans_action_signature_good (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Detect signature validation success, report as TRANS_SUCCESS
	return TRANS_FAILURE;
}

/* Report an error in signature validation.  This is an alternative to the
 * trans_action_signature_good.
 */
trans_retcode_t trans_action_signature_error (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	//TODO// Detect signature validation errors, report as TRANS_SUCCESS
	return TRANS_FAILURE;
}

/* Allow successful termination through a transition that swallows any
 * tokens still in transit and then ends the Petri net flow.  This is a
 * trivial transition that fires as soon as it can.
 */
trans_retcode_t trans_action_successfulEnd (
				PARMDEF_COMMA (pnc)
				transref_t tr,
				time_t *nowp,
				void *opt_evdata) {
	return TRANS_SUCCESS;
}

