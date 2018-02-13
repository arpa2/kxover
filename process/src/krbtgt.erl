% Management of the krbtgt tickets used for realm crossover.
%
% The tickets used are unidirectional; the client can reach the
% server (go from crealm to srealm) but not conversely.  The
% opposite direction is simply another KXOVER protocol run.
%
% From: Rick van Rein <rick@openfortress.nl>

-module( krbtgt ).


