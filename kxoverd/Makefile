CC=gcc
KRBPATH=/home/oriol/kerberos/krb5-1.13.2/src
CFLAGS=-g -O2 -I/usr/local/lib -I$(KRBPATH)/include -I$(KRBPATH)/lib -Wall -c
LDFLAGS=-lgetdns -lrt -lresolv -lssl -lcrypto -ltasn1
KRBLIBS=-Xlinker -rpath=$(KRBPATH)/lib $(KRBPATH)/lib/libkrb5.so $(KRBPATH)/lib/libcom_err.so $(KRBPATH)/lib/libkadm5srv_mit.so

all: kxoverd 

kxoverd: dispatch.o lookup.o tlsa_openssl.o asn1.o array.o ecdh_openssl.o util.o db.o request_list.o tgs_req.o as_req.o as_rep.o
	$(CC) dispatch.o lookup.o tlsa_openssl.o asn1.o array.o ecdh_openssl.o util.o db.o request_list.o tgs_req.o as_req.o as_rep.o $(LDFLAGS) -o kxoverd $(KRBLIBS)

lookup.o: lookup.c
	$(CC) $(CFLAGS) lookup.c
tlsa_openssl.o: tlsa_openssl.c
	$(CC) $(CFLAGS) tlsa_openssl.c
ecdh_openssl.o: ecdh_openssl.c
	$(CC) $(CFLAGS) ecdh_openssl.c
dispatch.o: dispatch.c
	$(CC) $(CFLAGS) dispatch.c
asn1.o: asn1.c
	$(CC) $(CFLAGS) asn1.c
tgs_req.o: tgs_req.c
	$(CC) $(CFLAGS) tgs_req.c
as_req.o: as_req.c
	$(CC) $(CFLAGS) as_req.c
as_rep.o: as_rep.c
	$(CC) $(CFLAGS) as_rep.c
util.o: util.c
	$(CC) $(CFLAGS) util.c
request_list.o: request_list.c
	$(CC) $(CFLAGS) request_list.c
array.o: array.c
	$(CC) $(CFLAGS) array.c
db.o: db.c
	$(CC) $(CFLAGS) db.c
clean:
	rm *.o deamon

