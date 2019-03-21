# Using KXOVER with MIT krb5

To use this building target, set `Kerberos5_SYSTEM=mitkrb5`
during CMake configuration.  We have prepared a
[demo setup of MIT krb5](https://github.com/arpa2/docker-demo).

The KXOVER solution was first developed for MIT krb5, as it
is probably the most widely spread open source form of
Kerberos, and home to a lot of knowledge and good support.

MIT krb5 has no dynamic facilities for inserting host-to-realm
mappings, but it can be extended with a DNSSEC resolver to
look for `_kerberos TXT` in DNS under a host name, as per the
[draft-vanrein-dnstxt-krb1](https://datatracker.ietf.org/doc/draft-vanrein-dnstxt-krb1/)
specification.

The current design of MIT krb5 uses processes, and is not
(completely) event-driven.  This means that external access
can bog down the KDC and even lead to stagnation of service,
up to denial-of-service problems.  This might be worked around
by limiting the number of processes waiting for DNSSEC output,
or the time they are willing to wait for it.  The reasoning
is that a cached version would pop up quickly enough, and if
no such entry exists then a fallback to the KXOVER wrapper
might help.  The KXOVER wrapper is event-based and will
resend a request when it found the data with Unbound; the
client is kept waiting during this time.

TODO:Unbound: Does the library share caches between processes?

