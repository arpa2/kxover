# Using KXOVER with Samba

To use this building target, set `Kerberos5_SYSTEM=samba`
during CMake configuration.  We have prepared a
[demo setup of Samba](https://github.com/arpa2/docker-demo).

We have not yet explored compatibility with Samba, but
expect it to work if we want to wrap KXOVER around it.
It may be an interesting step up to supporting MS AD.

