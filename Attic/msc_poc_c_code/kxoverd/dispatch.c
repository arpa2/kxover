#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/un.h>
#include <string.h>
#include "tgs_req.h"
#include "as_req.h"
#include "as_rep.h"
#include <krb5.h>

#define ADDRESS "/tmp/sckt"


void dispatch(krb5_data *pkt) {
	krb5_error_code retval;	

	if(krb5_is_tgs_req(pkt)) {
		retval = process_tgs_req(*pkt);
	}
	
	else if(krb5_is_as_req(pkt)) {
		retval = process_as_req(*pkt);
	}

	else if(krb5_is_as_rep(pkt)) {
		retval = process_as_rep(*pkt);
	}
}


int main() {
	char c[1024] = {""};
        int fromlen, ret;
        register int  s, ns, len;
        struct sockaddr_un saun, fsaun;
	krb5_data packet;

        if((s=socket(AF_UNIX, SOCK_STREAM,0)) < 0 ) {
                perror("server: socket");
                exit(1);
        }

        saun.sun_family = AF_UNIX;
        strcpy(saun.sun_path, ADDRESS);

        unlink(ADDRESS);
        len = sizeof(saun.sun_family) + strlen(saun.sun_path);

        if(bind(s, (struct sockaddr *)&saun, len) < 0) {
                perror("server: bind");
                exit(1);
        }

        if(listen(s,5) < 0) {
                perror("server: listen");
                exit(1);
        }
	fromlen = sizeof(fsaun);
        while(1) {
		puts("Listening...");
                if((ns = accept(s, (struct sockaddr *)&fsaun, &fromlen)) < 0) {
                        perror("server: accept");
                        exit(1);
                }
                while(1){
                        ret = recv(ns, c, sizeof(c), 0);
                        if(ret == 0) {
                                break;
                        }
			packet.data = c;
			packet.length = ret;
			dispatch(&packet);
                        memset(&c[0],0,sizeof(c));
			break;
                }
        }

        close(s);
        exit(0);

}
