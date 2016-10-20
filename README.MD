Kerberos Realm Crossover (using DANE)
=====================================

>   *The KXOVER daemon extends Kerberos’ Key Distribution Centres with a
>   secure, impromptu method for realm crossover.  Meaning, realms that never
>   met before have a secure method of exchanging Principal Names and session keys,
>   based on DANE and DNSSEC.*

Introduction
------------

TODO

Building
--------

TODO

Using
-----

TODO

Related Work
------------

**Realm in DNS:** The client’s KDC needs to discover the service’s realm name,
based on a server hostname.  This can be done with [\_kerberos
TXT](https://datatracker.ietf.org/doc/draft-vanrein-dnstxt-krb1/) records (which
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

-   Orial Caño ended his [TU/e](http://tue.nl) study signed up for [the
    project](https://research.arpa2.org/projects/2014-pkcross-dane.html) and
    wrote his [MSc
    thesis](https://research.arpa2.org/library/bellatriu-2016-kerberos-realm-crossover.pdf)
    about his proof-of-concept code

-   [SURFnet](https://www.surf.nl/over-surf/werkmaatschappijen/surfnethttps://www.surf.nl/en/about-surf/subsidiaries/surfsara/)
    funded the further development to setup a pilot project with [SURFsara]
    (https://www.surf.nl/en/about-surf/subsidiaries/surfsara/)
