# Using KXOVER with Microsoft Active Directory

To use this building target, set `Kerberos5_SYSTEM=ad`
during CMake configuration.

AD is not currently supported.  According to our
[early research](http://realm-xover.arpa2.net/kerberos.html),
it has a tendency to be less open in terms of connection
to other types of Kerberos software.

This software is closed-source, and comes in varieties,
possibly with differences in behaviour.  It may or may not
be possible to insert an intermediate layer such as KXOVER
implements.

We currently have no estimation of how difficult it would
be to incorporate AD.  The system is so vastly different
from others that we suggest a Windows expert turns to it.
We are happily looking forward to updates to our code in
order to support AD, inasfar as they are not too disruptive,
because we believe that security software should first and
foremost be simple and open source.  Note that first getting
Samba to work with KXOVER would be a good step up towards
allowing Active Directory to get on board.

