#!/bin/sh
#
# Generate keys for use with the test scripts
#
# From: Rick van Rein <rick@openfortress.nl>


#TODO# Don't know why this generates a PEM key in spite of the -keyform

if [ ! -r secp256k1.der ]
then
	echo 'Generating parameters in secp256k1.der'
	openssl ecparam -outform der -out secp256k1.der -name secp256k1
fi

if [ ! -r eckey.pem ]
then
	echo 'Generating new key under secp256k1.der parameters'
	openssl ecparam -name secp256k1 -inform der -in secp256k1.der -genkey -outform der -out eckey.der
fi

echo 'Generating new self-signed certificate (stripping off the AlgOID manually with dd...)'
dd if=eckey.der of=selfsig-key.der bs=1 skip=7
openssl req -new -x509 -nodes -keyform der -key selfsig-key.der -outform der -out selfsig-cert.der -days 3650

