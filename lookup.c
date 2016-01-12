#include "lookup.h"


int lookupTXT(char* query, int max, char* results[], int* size) {
	size_t num_addresses;
	getdns_return_t this_ret;
	getdns_context *this_context = NULL;
	getdns_return_t context_create_return = getdns_context_create(&this_context, 1);

	if(context_create_return != GETDNS_RETURN_GOOD) {
		fprintf(stdout, "Trying to create the context failed: %d\n", context_create_return);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}

	uint8_t this_request_type = GETDNS_RRTYPE_TXT;

	getdns_dict * this_extensions = getdns_dict_create();
	this_ret = getdns_dict_set_int(this_extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
	if(this_ret != GETDNS_RETURN_GOOD) {
		fprintf(stdout, "Trying to set an extension do both IPv4 and IPv6 failed: %d\n", this_ret);
	        getdns_dict_destroy(this_extensions);
        	getdns_context_destroy(this_context);
        	return(GETDNS_RETURN_GENERIC_ERROR);
	}
	/*this_ret = getdns_dict_set_int(this_extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE);
	if(this_ret != GETDNS_RETURN_GOOD) {
		fprintf(stdout, "Trying to set an extension do only dnssec secure failed: %d\n", this_ret);
	        getdns_dict_destroy(this_extensions);
        	getdns_context_destroy(this_context);
        	return(GETDNS_RETURN_GENERIC_ERROR);
	}*/
	getdns_dict * this_response = NULL;

	getdns_return_t dns_request_return = getdns_general_sync(this_context, query, this_request_type, this_extensions, &this_response);
	if(dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME) {
		fprintf(stdout, "A bad domain name was used: %s. Exiting.\n", query);
        	getdns_dict_destroy(this_response);
        	getdns_dict_destroy(this_extensions);
        	getdns_context_destroy(this_context);
	        return(GETDNS_RETURN_GENERIC_ERROR);
	}
	
	else {
		uint32_t this_error;
		this_ret = getdns_dict_get_int(this_response, "status", &this_error);
		if(this_error == GETDNS_RESPSTATUS_NO_SECURE_ANSWERS) {
			fprintf(stdout, "The search was not verified with DNSSEC and got a return value of %d. Exiting.\n", this_error);
            		getdns_dict_destroy(this_response);
            		getdns_dict_destroy(this_extensions);
            		getdns_context_destroy(this_context);
	        	return(GETDNS_RETURN_GENERIC_ERROR);
		}
		else if(this_error != GETDNS_RESPSTATUS_GOOD) {
			fprintf(stdout, "The search had no results, and a return value of %d. Exiting.\n", this_error);
            		getdns_dict_destroy(this_response);
            		getdns_dict_destroy(this_extensions);
            		getdns_context_destroy(this_context);
	        	return(GETDNS_RETURN_GENERIC_ERROR);
		}
		getdns_list * replies_tree;
		this_ret = getdns_dict_get_list(this_response, "replies_tree", &replies_tree);
		getdns_dict * this_answer;
		this_ret = getdns_list_get_dict(replies_tree, 0, &this_answer);
		
		getdns_list * answer;
		this_ret = getdns_dict_get_list(this_answer,"answer", &answer);
		
		this_ret = getdns_list_get_length(answer, &num_addresses);
	
		size_t rec_count;	
		for(rec_count = 0; rec_count < num_addresses && rec_count < max; ++rec_count) {
			getdns_dict * this_realm;
			this_ret = getdns_list_get_dict(answer, rec_count, &this_realm);
			
			getdns_dict * realm_name;
			this_ret = getdns_dict_get_dict(this_realm,"rdata", &realm_name);
			
			getdns_list * realm_txt;
			this_ret = getdns_dict_get_list(realm_name, "txt_strings", &realm_txt);
			
			char *this_realm_str = getdns_print_json_list(realm_txt,0);
			results[rec_count] = (char *)malloc(255*sizeof(char));
			strcpy (results[rec_count], this_realm_str);
			free(this_realm_str);
		}
	}
	getdns_dict_destroy(this_response);
    	getdns_dict_destroy(this_extensions);
    	getdns_context_destroy(this_context);
    	/* Assuming we get here, leave gracefully */
	*size = num_addresses;
	return(0);
}



int lookupSRV(char* query, char* target, int* port) {
	getdns_return_t this_ret;
	getdns_context *this_context = NULL;
	getdns_return_t context_create_return = getdns_context_create(&this_context, 1);

	if(context_create_return != GETDNS_RETURN_GOOD) {
		fprintf(stdout, "Trying to create the context failed: %d\n", context_create_return);
		return(GETDNS_RETURN_GENERIC_ERROR);
	}

	uint8_t this_request_type = GETDNS_RRTYPE_SRV;

	getdns_dict * this_extensions = getdns_dict_create();
	this_ret = getdns_dict_set_int(this_extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
	if(this_ret != GETDNS_RETURN_GOOD) {
		fprintf(stdout, "Trying to set an extension do both IPv4 and IPv6 failed: %d\n", this_ret);
	        getdns_dict_destroy(this_extensions);
        	getdns_context_destroy(this_context);
        	return(GETDNS_RETURN_GENERIC_ERROR);
	}
	/*this_ret = getdns_dict_set_int(this_extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE);
	if(this_ret != GETDNS_RETURN_GOOD) {
		fprintf(stdout, "Trying to set an extension do only dnssec secure failed: %d\n", this_ret);
	        getdns_dict_destroy(this_extensions);
        	getdns_context_destroy(this_context);
        	return(GETDNS_RETURN_GENERIC_ERROR);
	}*/
	getdns_dict * this_response = NULL;

	getdns_return_t dns_request_return = getdns_general_sync(this_context, query, this_request_type, this_extensions, &this_response);
	if(dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME) {
		fprintf(stdout, "A bad domain name was used: %s. Exiting.\n", query);
        	getdns_dict_destroy(this_response);
        	getdns_dict_destroy(this_extensions);
        	getdns_context_destroy(this_context);
	        return(GETDNS_RETURN_GENERIC_ERROR);
	}
	
	else {
		uint32_t this_error;
		this_ret = getdns_dict_get_int(this_response, "status", &this_error);
		if(this_error == GETDNS_RESPSTATUS_NO_SECURE_ANSWERS) {
			fprintf(stdout, "The search was not verified with DNSSEC and got a return value of %d. Exiting.\n", this_error);
            		getdns_dict_destroy(this_response);
            		getdns_dict_destroy(this_extensions);
            		getdns_context_destroy(this_context);
	        	return(GETDNS_RETURN_GENERIC_ERROR);
		}
		else if(this_error != GETDNS_RESPSTATUS_GOOD) {
			fprintf(stdout, "The search had no results, and a return value of %d. Exiting.\n", this_error);
            		getdns_dict_destroy(this_response);
            		getdns_dict_destroy(this_extensions);
            		getdns_context_destroy(this_context);
	        	return(GETDNS_RETURN_GENERIC_ERROR);
		}
		getdns_list * replies_tree;
		this_ret = getdns_dict_get_list(this_response, "replies_tree", &replies_tree);

		getdns_dict * this_answer;
		this_ret = getdns_list_get_dict(replies_tree, 0, &this_answer);
		
		getdns_list * answer;
		this_ret = getdns_dict_get_list(this_answer,"answer", &answer);
		
		
		getdns_dict * this_realm;
		this_ret = getdns_list_get_dict(answer, 0, &this_realm);
		
		getdns_dict * realm_name;
		this_ret = getdns_dict_get_dict(this_realm,"rdata", &realm_name);
				
		uint32_t this_port;
		this_ret = getdns_dict_get_int(realm_name, "port", &this_port);
		*port = this_port;
			
		getdns_bindata * this_bin_target;
		char* this_target;
		this_ret = getdns_dict_get_bindata(realm_name, "target", &this_bin_target);
		this_ret = getdns_convert_dns_name_to_fqdn(this_bin_target, &this_target);
		//target = (char *)malloc(255*sizeof(char));
		strcpy(target,this_target);
		free(this_target);
	}
	getdns_dict_destroy(this_response);
    	getdns_dict_destroy(this_extensions);
    	getdns_context_destroy(this_context);
    	/* Assuming we get here, leave gracefully */
	return(0);
}

int lookupTLSA(char* query, getdns_bindata * cert_data) {
        getdns_return_t this_ret;
        getdns_context *this_context = NULL;
        getdns_return_t context_create_return = getdns_context_create(&this_context, 1);

        if(context_create_return != GETDNS_RETURN_GOOD) {
                fprintf(stdout, "Trying to create the context failed: %d\n", context_create_return);
                return(GETDNS_RETURN_GENERIC_ERROR);
        }

        uint8_t this_request_type = GETDNS_RRTYPE_TLSA;

        getdns_dict * this_extensions = getdns_dict_create();
        this_ret = getdns_dict_set_int(this_extensions, "return_both_v4_and_v6", GETDNS_EXTENSION_TRUE);
        if(this_ret != GETDNS_RETURN_GOOD) {
                fprintf(stdout, "Trying to set an extension do both IPv4 and IPv6 failed: %d\n", this_ret);
                getdns_dict_destroy(this_extensions);
                getdns_context_destroy(this_context);
                return(GETDNS_RETURN_GENERIC_ERROR);
        }
        /*this_ret = getdns_dict_set_int(this_extensions, "dnssec_return_only_secure", GETDNS_EXTENSION_TRUE);
        if(this_ret != GETDNS_RETURN_GOOD) {
                fprintf(stdout, "Trying to set an extension do only dnssec secure failed: %d\n", this_ret);
                getdns_dict_destroy(this_extensions);
                getdns_context_destroy(this_context);
                return(GETDNS_RETURN_GENERIC_ERROR);
        }*/
        getdns_dict * this_response = NULL;

        getdns_return_t dns_request_return = getdns_general_sync(this_context, query, this_request_type, this_extensions, &this_response);
        if(dns_request_return == GETDNS_RETURN_BAD_DOMAIN_NAME) {
                fprintf(stdout, "A bad domain name was used: %s. Exiting.\n", query);
                getdns_dict_destroy(this_response);
                getdns_dict_destroy(this_extensions);
                getdns_context_destroy(this_context);
                return(GETDNS_RETURN_GENERIC_ERROR);
        }
        
        else {
                uint32_t this_error;
                this_ret = getdns_dict_get_int(this_response, "status", &this_error);
                if(this_error == GETDNS_RESPSTATUS_NO_SECURE_ANSWERS) {
                        fprintf(stdout, "The search was not verified with DNSSEC and got a return value of %d. Exiting.\n", this_error);
                        getdns_dict_destroy(this_response);
                        getdns_dict_destroy(this_extensions);
                        getdns_context_destroy(this_context);
                        return(GETDNS_RETURN_GENERIC_ERROR);
                }
                else if(this_error != GETDNS_RESPSTATUS_GOOD) {
                        fprintf(stdout, "The search had no results, and a return value of %d. Exiting.\n", this_error);
                        getdns_dict_destroy(this_response);
                        getdns_dict_destroy(this_extensions);
                        getdns_context_destroy(this_context);
                        return(GETDNS_RETURN_GENERIC_ERROR);
                }
                getdns_list * replies_tree;
                this_ret = getdns_dict_get_list(this_response, "replies_tree", &replies_tree);

                getdns_dict * this_answer;
                this_ret = getdns_list_get_dict(replies_tree, 0, &this_answer);
                
		getdns_list * answer_list;
                this_ret = getdns_dict_get_list(this_answer,"answer", &answer_list);

		getdns_dict * tlsa;
		this_ret = getdns_list_get_dict(answer_list, 0, &tlsa);

		getdns_dict * rdata;
		this_ret = getdns_dict_get_dict(tlsa, "rdata", &rdata);
		
		getdns_bindata * cert;
		this_ret = getdns_dict_get_bindata(rdata, "certificate_association_data", &cert);
		
		uint32_t usage;
		this_ret = getdns_dict_get_int(rdata, "certificate_usage", &usage);
		memcpy(cert_data, cert, sizeof(getdns_bindata));

        }
        getdns_dict_destroy(this_response);
        getdns_dict_destroy(this_extensions);
        getdns_context_destroy(this_context);
        /* Assuming we get here, leave gracefully */
        return(0);
}












