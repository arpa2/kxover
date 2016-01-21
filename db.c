#include "db.h"


void *handle = NULL;

int create_princ(char *princ_name, char *princ_pass) {
	kadm5_principal_ent_rec new_princ;
	long mask=0;
	krb5_error_code retval;
	krb5_context context;
	char *def_realm = NULL;
	char *svcname;
	kadm5_config_params params;
	char **db_args = NULL;
	char* keytab_name = NULL;



	memset(&params, 0, sizeof(params));

	//initialise context
	retval = kadm5_init_krb5_context(&context);
	if(retval) {
		com_err("kxover-deamon", retval, _("while initializing krb5 library"));		
		return retval;
	}
	
	/*	Initialise kxover principal 	*/
	/*	-> Get default realm		*/
	retval = krb5_get_default_realm(context, &def_realm);
	if(retval) {
		com_err("kxover-deamon", retval, _("while getting default realm"));		
		return retval;
	}

	/*	-> Configure parameters		*/
	params.mask |= KADM5_CONFIG_REALM;
	params.realm = def_realm;

	if(params.mask & KADM5_CONFIG_OLD_AUTH_GSSAPI)
		svcname = KADM5_ADMIN_SERVICE;
	else
		svcname = NULL;
	
	/*	-> Init with skey		*/
	retval = kadm5_init_with_skey(context, "kxover", keytab_name,svcname, &params, KADM5_STRUCT_VERSION,
					KADM5_API_VERSION_4, db_args, &handle);
	if(retval) {
		com_err("kxover-deamon", retval, _("while authenticating"));		
		return retval;
	}
	
	/*	Add principal to the DB		*/
	/*	-> parse name of the principal	*/
	retval = krb5_parse_name(context, princ_name, &new_princ.principal);
	if(retval) {
		com_err("kxover-deamon", retval, _("while parsing principal name"));		
		return retval;
	}
	
	new_princ.policy = "default";
	mask |= KADM5_POLICY;
	
	mask &= ~KADM5_POLICY_CLR;


	mask |= KADM5_PRINCIPAL;
	/*	-> create principal	*/
	retval = kadm5_create_principal(handle, &new_princ, mask, princ_pass);
	if(retval) {
		com_err("kxover-deamon", retval, _("while creating principal"));		
		return retval;
	}
	
	return 0;
}
