#include <krb5.h>
#include "lookup.h"



int process_tgs_req( krb5_data pkt) {
	krb5_error_code retval;	

	retval = decode_krb5_tgs_req(pkt, &request);
	if (retval)
		return retval;
	
}
