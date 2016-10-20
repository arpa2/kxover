Kerberos Realm Crossover (using DANE)
=====================================

>   *The KXOVER daemon extends Kerberos’ Key Distribution Centres with a
>   secure, impromptu method for realm crossover.  Meaning, realms that never
>   met before have a secure method of exchanging Principal Names and session keys,
>   based on DANE and DNSSEC.*

Introduction
------------

This package builds `kxoverd`, a stand-alone daemon that communicates with
remote KDCs.  In doing so, it uses DANE and DNSSEC to establish the security
of the remote; the remote is assumed to do the same in opposite direction.

The idea is that a KDC receiving a TGS-REQ for an unknown server hostname in
a domain that is not configured locally, can cross-over to another realm
with the following steps:

 1. Lookup the realm for the remote server in secure DNS
 2. Lookup the KDC's credentials for the remote server in secure DNS
 3. Exchange a key with the remote KDC
 4. Construct a TGS-REP and relay it back to the requester

The `kxoverd` daemon is a stand-alone program running on the same machine
as the KDC.  The implementation of KXOVER is stateless, with the exception
of some running state.  Any key established between realms is created in
the key database.

Crossover keys follow the form
```
krbtgt/OTHREALM@MYREALM
```
to allow any client in `MYREALM` to setup a session key to services in
`OTHREALM`.  This is normal for Kerberos; what KXOVER adds is a mechanism
to negotiate these crossover keys without manual intervention, purely based
on secure DNS mechanisms and direct communication between KDCs.

Crossover keys are usable in bulk, for any principal under `MYREALM` that
wants to access `OTHREALM` principals.  The opposite direction is not
supported with the same crossover key; a separate one may be negotiated
for that purpose.  It is polite, as a general principle, to consider playing
both roles.  Local authorisation settings should be prepared to distinguish
the local users from remote ones, and only grant access where this is warranted.

As you can tell, this is quite a change.  Kerberos is often setup as an
in-house or, at best, federated identity infrastructure.  With KXOVER, we
add a facility to make any realms interact.  As a result, Kerberos is
scaled up to the Internet at large.  This is a serious contender for a
market where provisioning of identities has a centralising tendency, quite
in contrast with the distributed nature that makes the Internet as potent,
failsafe and locally controllable as users would like.


Building
--------

To use `kxoverd`, first you need to patch your KDC.  In the current release,
we supply patches for MIT krb5 1.13.3.

Then build the code in the [kxoverd](kxoverd) directory, and run `kxoverd`
as a daemon on the same machine as the KDC.  The two will communicate through
a UNIX domain socket.  This has the disadvantage of not working remotely,
but it has the advantage of requiring no additional security precautions.


Using
-----

TODO

Note: Timeouts in clients may be problematic; this may be overcome by setting
up alternate SRV records in DNS to reach the server; the client will try each
in turn until a connection succeeds.  Something worth trying is to have a
fallback to TCP; timeouts are not necessarily enforced over TCP because there
is a clear notion of a connection, thus overruling UDP techniques.


Related Work
------------

**Realm in DNS:** The client’s KDC needs to discover the service’s realm name,
based on a server hostname.  This can be done with [\_kerberos
TXT records](https://datatracker.ietf.org/doc/draft-vanrein-dnstxt-krb1/) (which
is currently with the RFC Editor).

**Privacy:** Under KXOVER, a ticket can be obtained to securely access any
remote service.  When doing this, we do share our client identity.  Kerberos
offers [Anonymity Support](https://tools.ietf.org/html/rfc6112), but when we
hand out no details about our identity we cannot recall information from an
earlier session.  In the service of privacy, it would be good to have
[Pseudonymity
Support](https://tools.ietf.org/html/draft-vanrein-kitten-krb-pseudonymity) as
well.


Thanks
------

This project is initiated by ARPA2, as part of the [InternetWide
Architecture](http://internetwide.org/blog/2016/06/24/iwo-phases.html) which
aims to give users of the Internet control over their online presence.  This
project is a first step to [Bring Your Own
IDentity](http://internetwide.org/blog/2015/04/22/id-2-byoid.html) based on an
“IdentityHub” under your own control.

The following parties, in order of appearance, have contributed to this project:

-   [NLnet](http://nlnet.nl) and [OpenFortress](http://openfortress.nl)
    collaborated to initiate the [InternetWide](http://internetwide.org) /
    [ARPA2](http://arpa2.net) project

-   Orial Caño Bellatriu ended his [TU/e](http://tue.nl) study signed up for [the
    project](https://research.arpa2.org/projects/2014-pkcross-dane.html) and
    wrote his [MSc
    thesis](https://research.arpa2.org/library/bellatriu-2016-kerberos-realm-crossover.pdf)
    about his proof-of-concept code

-   [SURFnet](https://www.surf.nl/over-surf/werkmaatschappijen/surfnethttps://www.surf.nl/en/about-surf/subsidiaries/surfsara/)
    funded the further development to setup a pilot project with [SURFsara]
    (https://www.surf.nl/en/about-surf/subsidiaries/surfsara/)

