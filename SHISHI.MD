# Using KXOVER with Shisi and Shisa

To use this building target, set `Kerberos5_SYSTEM=shishi`
during CMake configuration.  We have prepared a
[demo setup of Shishi](https://github.com/arpa2/docker-demo).

Shishi implements RFC 1510, not RFC 4120.  This might lead
to unforeseen problems.  We have found that
[manual realm crossover works](https://github.com/arpa2/docker-demo/blob/a9ea18f8fe53ef8f01dfc5733a2aa5329d225e7b/demo-shishi/README.MD#realm-crossover),
for which it only uses the key management utility Shisa.
Although Shisa is touted to be idenpendent key management
software that could work with other software than just
Shishi, for 1.0.2 we had to resort to the `pkg-config`
of Shishi, thus including libraries for both packages.

Shishi is not currently supported, and it is sufficiently
different from the other solutions to take some time to
get going.  Having said that, its simplicity is a benefit
and might actually make it quite easy.

Shishi has no dynamic facilities for inserting host-to-realm
mappings, but it might be extended with a DNSSEC resolver to
look for `_kerberos TXT` in DNS under a host name, as per the
[draft-vanrein-dnstxt-krb1](https://datatracker.ietf.org/doc/draft-vanrein-dnstxt-krb1/)
specification.

