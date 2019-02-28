% Management of the krbtgt tickets used for realm crossover.
%
% The tickets used are unidirectional; the client can reach the
% server (go from crealm to srealm) but not conversely.  The
% opposite direction is simply another KXOVER protocol run.
%
% From: Rick van Rein <rick@openfortress.nl>


-module( krbtgt ).

-export([
	construct/2
]).

-include( "RFC4120.hrl" ).


% Given an #'EncTicketPart', construct a #'Ticket'.  This will copy
% a few fields into the outer part, and encrypt the inner part.
%
% The Ticket is encrypted for the indicated Principal@REALM, for
% KXOVER the form is always "krbtgt/SERVER.REALM@CLIENT.REALM".
% This service name is used to find the encryption key.
%
encrypt_ticket( Encpart,Principal,REALM ) ->
	Encdata = Encpart,   %TODONOW% actually encrypt the ticket
	Ticket = #'Ticket' {
		'tkt-vno' = 5,
		'sname' = Principal,
		'realm' = REALM,
		'enc-part' = Encdata
	},
	Ticket.


% Construct a krbtgt, so a Kerberos5 Ticket, from the given
% data structure holding tags for crealm, srealm, etype and
% kvno.
%TODO% renew_until, inuse_since, inuse_until, setup_keyex?
%
construct( AppData,SharedKey ) ->
	ClientRealm = maps:get( crealm,AppData ),
	ServerRealm = maps:get( srealm,AppData ),
	%UNUSED% SetupKeyex = maps:get( setup_keyex,AppData ),
	InUseUntil = maps:get( inuse_until,AppData ),
	%POINTLESS% RenewUntil = maps:get( renew_until,AppData ),
	InUseSince = maps:get( inuse_since,AppData ),
	%
	% We currently have no use for any ticket flags.
	% Perhaps renewable, one day, but it may be too complicating
	% while it adds too little.
	%
	Flags = 0,
	Principal = #'PrincipalName' {
		'name-type' = 2,
		'name-string' = [ "krbtgt", ServerRealm ] },
	ToBeEncTicketPart = #'EncTicketPart' {
		flags = Flags,
		key = SharedKey,
		crealm = ClientRealm,
		cname = Principal,
		transited = "",
		starttime = InUseSince,
		%TODO_USE_SETUPDATA% authtime = SetupTime0,
		authtime = InUseSince,
		%POINTLESS% use authtime from previously released ticket
		%POINTLESS% 'renew-till' = RenewUntil,
		endtime = InUseUntil
	},
	Ticket = encrypt_ticket (ToBeEncTicketPart, Principal, ClientRealm),
	Ticket.

