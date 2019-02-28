This is the `kxoverd` daemon program.  It runs on the same host as the KDC,
and is provided with messages from a suitably patched KDC process over a
UNIX domain socket.

This daemon code inserts realm-crossover keys into the KDC's database of
keys.  These are normal keys for realm crossover, but they may be rolled
and they require no manual intervention by an administrator or two.

The daemon is a separate process because it needs write access to the
principal database, which is not generally desirable for the KDC.  The
reason to run the two processes over a UNIX domain socket, thus requiring
them to run on the same machine, is that this simplifies communication to
an unencrypted exchange, and also because the type of hardened machine
that is fit to run a KDC is required, making it unlikely that the two
will be split, also because the key database needs to be accessible to
the two processes.

The initial proof of concept for this work was an MSc project by Oriol Caño
Ballatriu, under guidance and support of Rick van Rein, the architect of the
InternetWide.org project.  It has then be further developed with a grant
from SURFnet to turn it into a suitably stable and complete software product.

