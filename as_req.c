#include "as_req.h"


int process_as_req( krb5_data pkt) {
	krb5_error_code retval;
	krb5_as_req * request = 0;


	retval = krb5_init_context(&context);
	if(retval) {
		com_err("kxover-deamon", retval, "while initiating context");
		return retval;
	}

	retval = decode_krb5_as_req(&pkt, &request);
	if(retval) {
		com_err("kxover-deamon", retval, "while decoding request");
		return retval;
	}

}
