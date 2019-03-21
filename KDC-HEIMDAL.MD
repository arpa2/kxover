# Using KXOVER with Heimdal

To use this building target, set `Kerberos5_SYSTEM=heimdal`
during CMake configuration.  We have prepared a
[demo setup of Heimdal](https://github.com/arpa2/docker-demo).

Heimdal is not currently supported.  It is very similar to
MIT krb5, so the work to get it going should not be
excessive.

Heimdal has no dynamic facilities for inserting host-to-realm
mappings, but it can be extended with a DNSSEC resolver to
look for `_kerberos TXT` in DNS under a host name, as per the
[draft-vanrein-dnstxt-krb1](https://datatracker.ietf.org/doc/draft-vanrein-dnstxt-krb1/)
specification.

