#!/bin/sh

if [ -x /etc/kxover ]
then
	echo 'FATAL: You have /etc/kxover/ and presumably the "kxover/public" identity?'
	exit 1
fi

mkdir /etc/kxover
( echo addprinc -randkey kxover/public ; echo ktadd -k /etc/kxover/public.keytab kxover/public ; echo quit ) | kadmin.local

grep -q kxover/public /etc/krb5kdc/kadm5.acl
if [ $? == 1 ]
then
	echo 'You want to mention kxover in /etc/krb5kdc/kadm5.acl'
	echo 'For instance: kxover/public@YOUR.REALM admcil *'
else
	echo 'Found kxover/public in /etc/krb5kdc/kadm5.acl'
	echo 'Assuming it is correct'
fi

echo 'You can test with something like:'
echo 'time kadmin -p kxover/public -k -t /etc/kxover/public.keytab -s <server-IP> list_principals'
