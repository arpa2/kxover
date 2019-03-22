# KXOVER and Infrastructure

> *This document spells out the required and possible relationships
> between KXOVER and the remaining network, notably KDC and DNS.*

KXOVER collaborates with KDCs to establish realm crossover keys.
This is an automatic procedure, that can be fast enough for impromptu
realm crossover, where the interesting part is that the KDC may have
to respond in a timely manner because clients may not be waiting
for more than a few seconds.

The Dutch may pronounce KXOVER as "klaar-over".

## KXOVER as a Protocol

The KXOVER protocol runs strictly over TCP.  It usually shares the
port for the KDC, so its SRV record is `_kerberos._tcp.REALM.NAME`
and will often point to TCP port 88.

KXOVER packets are distinguished from other Kerberos packets by
their initial tagging, which is the DER coding 0xTODO for
`[APPLICATION 18]` for a KXOVER request, of 0xTODO for
`[APPLICATION 19]` for a KXOVER response.  Regular Kerberos
messages also use `[APPLICATION nn]` tags, but these do not
occur in any RFC.

## KXOVER as a Kerberos Wrapper

It is possible to run KXOVER directly on TCP port 88.  When it
is configured with a redirection address for the KDC, it may
relay default Kerberos messages to a KDC over TCP, which may
also be used as a mechanism to publish an internal Kerberos
on the external Internet, possibly through a format-scrutinising
intermediate.

KXOVER will not listen to UDP.  There are no fundamental
reasons for it, other than that it seems to make more sense
to reserve UDP for the much faster normal operation of KDCs.

When traffic to a KDC passes through and a request for a
ticket is refused due to an unknown realm, then KXOVER
might intervene by constructing a crossover ticket, but
that would only service TCP queries, and it would be
subjected to the ability to decode requests, thus sharing
internally held keys.

### Minimal Effort for a KDC

The KDC will need to interact slightly with KXOVER.
Specifically, it will need to know that a host belongs
under a certain realm.  There are two ways of doing
this:

 1. Through [draft-vanrein-dnstxt-krb1](https://datatracker.ietf.org/doc/draft-vanrein-dnstxt-krb1/)
    which means looking up `_kerberos` TXT records under
    the host name and taking out the first string to get
    the realm for that host.  DNSSEC is required for this
    to work.

 2. Through a database with host-to-realm setups that is
    managed by KXOVER, and with a timeout on each entry.
    KXOVER can detect failures to access a host, make the
    necessary arrangements up to and including insertion
    of a host-to-realm mapping in this database, and the
    request could be resent.  The KDC would then find
    the newly added mapping and continue.

The second option offers better isolation and is more
general.  It is also easier on the KDC, especially
because it can reject any unknown host-to-realm mapping
immediately, and have KXOVER pickup on it without even
having to wait until a DNSSEC lookup whose information
the KDC will not be able to use.

Only in cases where realm crossover has been setup is
it quicker to handle this directly in the KDC.  But
even then it is probably better to treat a new host
(and its timeout constraints) as a non-KDC issue, for
the sake of simplicity, and its impact on security.

As for this external database, a very simple format
can be considered.  It can just be the `_kerberos` TXT
format taken out of the DNSSEC cache of KXOVER, but
possibly constrained to realms that are known to be
good.  KXOVER can in fact learn if it sees a host
showing up again when a realm crossover key is nearing
its end-of-life; the crossover can then be refreshed.

In terms of configuration, this requires a DNS service
to be configured for the host-to-realm mapping, and
this is independent of the rest of the queries that a
KDC might want to make.

When a KDC refuses a request and KXOVER resends it,
there may be a problem due to the matching `Nonce`
and other fields: the KDC may think it is finished,
even when the situation may have advanced.  This is
another point where some more leeway may be needed.


## KXOVER as a Kerberos CA

Instead of intervening in traffic between KDC and client,
KXOVER functions as a CA that can be configured in a normal
KDC.  This CA can be asked about any realm, so it is
normally configured to serve the domain name `.` and anything
below it.  It is however possible to assign the CA role
only for dedicated realms, which presents the KDC with a
key-rolling substitute for manual keying between realms.

Federations are not advised to employ KXOVER as a CA for
a dedicated list of domains; they have a more flexible
option when the entire `.` domain is covered, but a
federation root certificate is enforced.  It is even
possible for KXOVER to be configured with more than one
federations in which to participate by listing multiple
root certificates; the largest selection would then be
a list of public CA roots, leading to activity over the
entire Internet.

By playing the role of a CA, KXOVER can be a server for
both UDP and TCP clients of a KDC.  KXOVER itself would
be contacted only over TCP.  In this role, a KDC may
request `krbtgt/REMOTE.REALM@LOCAL.REALM` tickets, and
address them to a service that has its own key.  This
means that the CA must be paired with the KDC by sharing
this key, and that the CA limits service to particular
peers.  It can however address multiple CAs.  It is not
likely that this function mixes easily with the
TCP wrapper function, though it may not be completely
impossible either.

As a CA, KXOVER can return the requested tickets for
realm crossover, without a need to add them to the
KDC's key store.  There would be an expiration time
on each of the keys, so the KDC can manage them
properly.

TODO: Is this indeed how the CApath function works?

## Dealing with Impatient Clients

Client software does not know if the KDC is setting up
public-key crypto exchanges with other realms to answer
to a request; it will simply be supplied with a
forwarding ticket for another realm, and is expected to
follow them under the now customary TODO:canonicalisation
extension.

UDP is a particularly poor carrier for this kind of
service, because it provides not feedback or assurance
that a KDC is working.  The Kerberos protocol lacks a
"please hold, I'm working for you" notification.

It is however possible to define fallback service,
either over UDP or TCP, and a client is expected to
try these services when a first attempt fails.  This
would then be used to retry, demanding the same realm
crossover and therefore continuing an already-started
KXOVER exchange.  The KXOVER service collects inquiries
for the same realm crossover tickets, and answers them
all at once, then using much faster symmetric keying.

An awkward trick that is likely to work with seconds
that leave after 2 seconds or less is to define more
than one `_kerberos._udp.REALM.NAME` SRV records,
and/or more than one IP address for the appointed host.
Probably a better approach is to fallback to TCP,
in the reasonable hope the clients will be more patient
about a connection that is sitting around.

Clients may well be updated to accept longer delays
when they become aware of realm crossover as a
possible cause, but there may always be retired
software that is still being used (which is a security
problem in itself) and that kind of software might be
remedied with fallback server mentions.

## KXOVER and DNS

The based records that KXOVER needs in DNS are
SRV and TLSA records.  These should be signing
under DNSSEC, as this is only forcefully
validated in places where this is a security
requirement, and denial of service is remedied
by DNSSEC in other places.

The SRV record is named `_kerberos._tcp.REALM.NAME`
and it serves a double role; it both acts as a
server, taking in KXOVER requests from clients
in other realms, and it can act as a relay to a
KDC in the backend.  Since the record implies
expectations with the client, this relay function
is strongly encouraged, though a connection will
get reset after a KDC error when such configuration
is missing.  In other words, the TCP record need
not add any delay when rejecting clients.

The TLSA record is for the TCP protocol and at
least one of the ports defined with an SRV
record.  Only host/port combinations with a
TLSA record would get KXOVER clients connected
to, under the assumption that the TLSA record
can be used to validate that connection.

## KXOVER and Peer Validation

Every KXOVER request or response holds a common
and symmetric packet named the KX-OFFER.  This
packet is digitally signed with public key crypto,
and mentions the certificate chain used.

The certificate chain is the complete path from
end certificate to root certificate, the latter
always being a self-signed certificate.  The
simplest chain consists of precisely one
self-signed certificate, but complete hierarchies
can also be supported.  Only X.509 certificates
are supported.

To validate a peer, the following checks are
applied:

 1. The KX-OFFER is in line with local policies;
    this involves algorithms and key size settings
    as well as realms requested and offered.

 2. The remote realm hosts the proper SRV and TLSA
    records, signed with DNSSEC under enforcement
    inasfar as this is required for KXOVER.

 3. The certificate chain is a non-empty sequence
    of certificates where each former signs the next;
    and where the last certificate is self-signed.
    There is no restriction to forbid self-signed
    certificates in other chain positions, as that
    may some day be useful for CA cross-signing.

 4. DANE rules from the TLSA record apply to the
    certificate chain in use.

 5. When configured with root certificates under
    which trust is operated, then the last certificate
    in the chain must be one of those root
    certificates.  This mechanism enables a public
    CA to be an additional constraint for KXOVER,
    and it also allows membership of one or more
    federations.

 6. The KX-OFFER contains a signature and signed
    data that validate as being signed by the first
    certificate in the chain.

## KXOVER and Quantum Computing

The current key exchange mechanism for KXOVER is
ECDH with ephemeral keys, but that will break
instantly when Quantum Computing arrives.  The
result of that would be that all stored traffic
between two realms connected by KXOVER could be
decrypted.

As soon as quantum-computing resistant mechanisms
for key exchange are established it is advisable
to switch to those; but there is much we can do
until then to combat the threat.

Once realm crossover has been established, it is
possible for KXOVER to roll from one key to the
next while incorporating prior crossover keys.
This means that a long historic trace can be
held that only decrypts when the entire trace
has been tapped and stored.

One of the things that KXOVER can do is to keep
linking to a remote realm even when no clients
are currently asking for it; the number of such
proactive renewals can be configured.  It is not
just interesting as protective measure against
Quantum Computing, but it also speeds up future
access of a realm.

One can think of rather contrived schemes, but
a few easy ones are Manual Keying and
Peer Service.

## KXOVER and Manual Keying

Before KXOVER, realm crossover was a matter
of manual configuration.  Any keys that have
been, or will be, configured in that fashion
are still useful.

Manually set keys can improve the amount of
entropy available during crossover, just
like preceding keys that are being rolled.
To make this possible, the realms should
be interested in using KXOVER instead of the
manually established key; for example because
the latter is very old.  Also, KXOVER must
be able to get hold of the key material.
Given that, it is possible to incorporate
the once-exchanged manual material as part
of a rolling scheme for KXOVER and, by that,
add entropy to the key exchange that defies
the most zealous taps on communication.

It is desirable to continue to use manual
keying for any out-of-band traffic.  This
is best done when communicated between
humans, in person or over a non-standard
channel.  This means that it is helpful to
use individual approaches and start keying
in one's natural environment.

## KXOVER as Peer Service

When looking for authority, we tend to look
up; when looking for entropy, it is probably
a better idea to look down, where the
opportunities for diversity and scattering
are better.

In terms of KXOVER, we might consider asking
clients that once crossed over to help us;
servers asking clients appears strange, but
is in truth just peer service.  The client
is a KDC as well, and should not mind.
Note that there may be a bidirectional
relationship between two KDC's, but that
it is the role as a client that hints us
about a path that is at least not sorted
upwards from us, and that should have a
tendency to help us out in return for
services rendered to them.  It is also a
good idea to skip realms of which our realm
is a sub-realm.

Taken to full length, a peer-to-peer
network passes requests in multiple hops.
When we are looking for entropy, such as
during an initial exchange with a realm,
we care less about the depth of the path,
and more about its breadth.  So, we would
rather use a single hop, but a few of
those (three sounds like a nice number).

So let's say we are `CLIENT.REALM` and we
want to setup a fresh relation with
`SERVER.REALM` for which we have insufficient
initial entropy to feel protected from a
Quantum-Computer crack of our ECDH exchange.

We lookup a number of our clients for realms
like `MIDDLE.REALM` and ask them for a ticket
named `krbtgt/SERVER.REALM@MIDDLE.REALM`
which is precisely the one that we are after.

Now if `MIDDLE.REALM` has a crossover ticket
to `SERVER.REALM`, it will supply it to us,
based on the relationship we already have with
a ticket `krbtgt/MIDDLE.REALM@CLIENT.REALM`
(that is a client ticket in reverse!)
but if it does not have this ticket, it can
decide to help out, on the grounds that we
pretty much rubbed their nose into the fact
that they are our client and that we need
help this time.  A client should be willing to
respond to such requests, as long as it
occurs in reasonable volumes.

The client now orders the crossover certificate
via KXOVER, and delivers it as it would have
when directly connected.  The client may or
may not stash the ticket; it is not useful to
cache it for `CLIENT.REALM` because our realm
now has entropy that can now be rolled into
future access to this realm.  This choice may
be reflected in a shorter duration than normal
for the requested crossover ticket, but it
need not.

We shall not rely on authentication claims
for this peer-provided ticket; instead, we
shall harvest entropy from the key to the
`SERVER.REALM` which is shared with that
realm, and can be used in a KXOVER rollover
request by mentioning its `kvno` value.
Although a client is now in the position to
commit a denial of service on this rollover,
the `SERVER.REALM` is likely to remove any
keys that it does not recognise and when
the result does not fit `CLIENT.REALM`
preferences, it is possible to restart the
endeauvour, and roll over while still
incorporating this key that we considered too
light.

What happens with this mechanism, is that the
patterns of access get blurred through
distribution.  And a few helpful clients can
improve the entropy available for initial
realm crossover in a manner that is not easy
to predict, even given the promise of future
power of Quantum Computing would allow to
retrace (most of) our steps.  Only one of
those steps needs to break before the entire
decryption of our traffic fails.

Note how nicely this approach combines with
Manual Keying for bootstrapping a trusted
network.  Also note how much sense it makes,
both in terms of entropy and reasonable use
of peer resources, to rely on clients that
have rolled keys many times with us, but to
offload casual visitors.  This is the general
tendency of current-day protection from
Quantum Computing, to build stable relations
and maintain them, while collecting entropy.


