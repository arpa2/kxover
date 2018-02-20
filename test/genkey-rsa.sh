#!/bin/sh
#
# Generate keys for use with the test scripts
#
# From: Rick van Rein <rick@openfortress.nl>


#TODO# Don't know why this generates a PEM key in spite of the -keyform

openssl req -x509 -nodes -newkey rsa:2048 -outform der -keyform der -out selfsig-cert.der -keyout selfsig-key.der -days 3650

