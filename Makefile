CC=gcc
CFLAGS=-g -O2 -I/usr/local/lib -I/home/oriol/kerberos/krb5-1.13.2/src/include -I/home/oriol/kerberos/krb5-1.13.2/src/lib -Wall -c
LDFLAGS=-lgetdns -lrt -lresolv -lssl -lcrypto 
KRBLIBS=-Xlinker -rpath=/home/oriol/kerberos/krb5-1.13.2/src/lib /home/oriol/kerberos/krb5-1.13.2/src/lib/libkrb5.so /home/oriol/kerberos/krb5-1.13.2/src/lib/libcom_err.so /home/oriol/kerberos/krb5-1.13.2/src/lib/libkadm5srv_mit.so

all: deamon 

deamon: dispatch.o lookup.o util.o db.o tgs_req.o 
	$(CC) dispatch.o lookup.o tlsa_openssl.o util.o tgs_req.o $(LDFLAGS) -o deamon $(KRBLIBS)

lookup.o: lookup.c
	$(CC) $(CFLAGS) lookup.c
tlsa_openssl.o: tlsa_openssl.c
	$(CC) $(CFLAGS) tlsa_openssl.c
ecdh_openssl.o: ecdh_openssl.c
	$(CC) $(CFLAGS) ecdh_openssl.c
dispatch.o: dispatch.c
	$(CC) $(CFLAGS) dispatch.c
tgs_req.o: tgs_req.c
	$(CC) $(CFLAGS) tgs_req.c
util.o: util.c
	$(CC) $(CFLAGS) util.c
db.o: db.c
	$(CC) $(CFLAGS) db.c
clean:
	rm *.o deamon

