KXOVER validation with DANE
===========================

>   *Implementing KXOVER with the TLS Pool and PKINIT certificates, we need to
>   carefully assign responsibilities.*

The following standards apply:

-   [RFC 6251](https://tools.ietf.org/html/rfc6251) defines a STARTTLS extension
    flag for Kerberos over TCP;

-   [RFC 5021](https://tools.ietf.org/html/rfc5021) defines flags as a general
    extension to Kerberos over TCP;

-   [RFC 4556](https://tools.ietf.org/html/rfc4556) defines PKIX certificates
    with principal\@REALM names;

-   [RFC 6698](https://tools.ietf.org/html/rfc6698) defines DANE;

-   [RFC 4120](https://tools.ietf.org/html/rfc4120) defines Kerberos version 5;

-   we demand all-uppercase REALM names in the DNS name style.

The authenticity for KXOVER involves the following tests against the remote
peer, regardless of its role as client or server:

-   The host name should be used as a CN in the KDC certificate, thus hinting
    over TLS what the server name will be.

-   The realm name is mapped to a DNS name.  This domain must point to the KDC
    with SRV records that use the STARTTLS-hinting prefix labels
    `_kerberos-tls._tcp` to the DNS name for the realm.  DNSSEC is required for
    these fields because they supply information for DANE.

-   For each SRV record, the port number and host name combine to prefix labels
    `_$(PORT)._tcp` to form a name for DANE.  This name is used to retrieve the
    TLSA records that help to constrain the certificate used for STARTTLS.
    DNSSEC is required for these fields because the remote KDC keying has no
    other basis for security in the general case.

-   The PKIX certificate used by the remote party holds the realm identity as a
    subjectAlternativeName, namely one or more GeneralName fields, each holding
    `krbtgt/$(REALM)@$(REALM)` to identify the KDC.  The realm questioned
    should/must be listed.  Only this format is acceptable; other services would
    not identify the KDC and differences in REALM could allow a man in the
    middle.

KXOVER Validation Procedure
---------------------------

The client connects to the server, knowing the realm names and having found host
names for both ends.  The server knows nothing yet.  During STARTTLS, both end
points offer a certificate, so afterwards each side knows both host names as
well as a list of realm names.  The TLS Pool returns the primary identity, which
is the host name of the KDC for the local and remote end point.  The client can
verify them to avoid talking to a wrong party, the server can accept an
arbitrary client as it is open to all.

The TLS Pool on each end now has KDC host names, which it can use to validate
their certificates against DANE.  Note that DNSSEC-protected SRV records should
have been used by the client to find the host name, but the TLS Pool remains
unaware of that.  All it cares about is the TLS host name, as indicated by DANE.

The client wants to contact a certain realm name, and can verify its existence
on the server against the remote certificate.  It may also verify that its local
KDC is able to service its local realm, though that may be better avoided by
proper configuration.

The client now sends a `KX-REQ` request message, holding a `KX-OFFER` message.
The service now knows both realm names too, and may verify those.  It must
validate that the client KDC offers the remote realm, but it should also verify
that the service realm is locally services, through the certificate or through
configuration.

The service must now ensure that the host name for the client matches an SRV
record for the KDC, which it can request in DNSSEC-protected DNS.  The resulting
list of names should include the name offered by the certificate, and validated
through DANE.  It is additionally possible to perform an AAAA or A lookup to
retrieve the IP addresses under the host name, a list that would have to include
the remote address.  Note that ports are less of a concern, given that a KXOVER
client may come from another port than the KDC public port over which it offers
TCP with STARTTLS.

Both ends have now validated the link from realm to domain name, on to KDC host
names and optionally their addresses, and on to TLSA records that validate the
certificates used with STARTTLS.

Changes to PKIX Certificates
----------------------------

The certificates used for this procedure are similar to those of PKIX, and may
certainly be combined.  The one difference is a requirement of a CN field in the
Subject field, which holds the host name.  This is not required for PKIX but it
is common practice in other server certificates.

We use the CN field in the Subject to learn about the KDC host name, as a
starting point for DANE.  We also use it as to fixate the SRV record checks to
one host name, which improves efficiency compared to the two-level DNSSEC
queries involved in first performing SRV queries followed by TLSA queries for
all the hosts listed in SRV records.

There is some variation in the type-name used in the SubjectAlternativeName
extension.  TODO: Follow RFC 4120 and use 2, or follow krb5 instructions and use
1, or interpret more so we can ignore the difference?

Changes to the TLS Pool
-----------------------

The current TLS Pool will undergo two changes to accommodate this scheme; this
is reasonable because the facilitation is generally useful:

-   Non-blocking communication with an event-aware API will allow KXOVER to be
    implemented in an asynchronous manner;

-   After a TLS handshake has come through, the remote certificate may be
    compared to a subjectAlternativeName.  In general, a certificate holds a
    list of such names, and the test will be if one of those matches the one
    provided for testing.

Changes to the KDC
------------------

The bump-in-the-wire approach leaves surprisingly little to be desired from the
KDC.  Most everything can be tapped and redirected.  But we are not completely
lucky:

-   The KDC should know that it must crossover to a realm for an unknown host
    name.  A middle man cannot do this, because it should not know the client
    key.  This can be done in a number of ways:

    -   The mapping from hostname to realm is updated dynamically;

    -   We somehow extend the KDB to hold a similar mapping;

    -   The KDC itself checks `_kerberos TXT` for hosts not found.

-   Not required, but probably useful: The crossover database was a separate
    database, overriding the customary database for crossover attempts, stored
    with its own access rights.  Especially when the crossover is triggered by a
    `_kerberos TXT` lookup in the KDC itself, this should leave no questions
    with the KDC about which way to turn.  This improves security by separating
    administration of local users and machines from online-derived crossover
    tickets.
