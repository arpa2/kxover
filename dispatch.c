#include <krb5.h>



void dispatch(krb5_data *pkt) {
	krb5_error_code retval;	

	if(krb5_is_tgs_req(pkt)) {
		retval = process_tgs_req(pkt);
	}
	
	else if(krb5_is_as_req(pkt)) {
		retval = process_as_req(pkt);
	}

	else if(krb5_is_as_rep(pkt)) {
		retval = process_as_rep(pkt);
	}
}
