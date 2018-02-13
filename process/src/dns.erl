% DNS routines for KXOVER.
%
% DNS records are really simple and really consistent in structure.
% The code below takes apart any output that we got from Unbound.
% Unbound handles all the difficult protocol aspects and outputs a
% proper structure with the information to evaluate its security
% before we process these records; once delivered by Unbound and
% accepted by our use of it, we can use these Erlang procedures to
% parse the code.
%
% From: Rick van Rein <rick@openfortress.nl>


-module( dns ).

-export([
	bin2dotted/1,
	srvrdata2parsed/2,
	srvrdata2sorted/2,
	srvrdata2sorted/1,
	srv2protoport/1,
	tlsardata2parsed/3
]).

-type protocol()  :: tcp | udp | sctp.

-type priority()  :: integer().
-type weight()    :: integer().
-type protoport() :: integer().
-type hostname()  :: binary().
-type srvrecord() :: { priority(),weight(),protoport(),hostname() }.

-type tlsa_certusage() :: ca_constraint | cert_constraint | ta_assertion | domain_issued_cert.
-type tlsa_selector()  :: full_cert | pubkey.
-type tlsa_matchtype() :: exact | sha256 | sha512.
-type tlsarecord()     :: { protocol(),protoport(),tlsa_certusage(),tlsa_selector(),tlsa_matchtype(),binary() }.


-define(LambdaLift2(Atom), fun(X,Y) -> Atom( X,Y ) end).


% Given a wire representation of a DNS name, present the
% dotted-label string of a FQDN (with trailing dot).
%
% Note that Unbound has taken care of DNS compression,
% so the wire format can be taken out of their context
% and we only have to deal with complete names.
%
%TODO% Prefer to use binaries for composed labels -- or compare label by label
bin2dotted( WireName ) ->
	% [ Y || <<X:8,Y:X/binary>> <= <<3,110,115,49,6,122,117,114,105,99,104,4,115,117,114,102,3,110,101,116,0>> ]
	Labels = [ Label || << 0:2,LabelLen:6,Label:LabelLen/binary >> <= WireName ],
	RootLen = size( lists:last( Labels )),
	if RootLen > 0 ->
		error (no_fqdn);
	true ->
		lists:join( '.',Labels )
	end.


% Compare two SRV records, returning true when L < R.
% The inputs are written as
%  { priority(),weight(),protocol(),protoport(),hostname() }
%
-spec srvless( srvrecord(),srvrecord() ) -> boolean().
%
srvless( { PrioA,WgtA,_,_,_ }, { PrioB,WgtB,_,_,_ }) ->
	if PrioA < PrioB ->
		true;
	PrioA > PrioB ->
		false;
	true ->
		% The following may be slightly wrong, but
		% since this is all random, it does not
		% matter much (and may actually be right).
		% Problem is that we're comparing pairs,
		% without overviewing the whole list and
		% taking knowledge of the sorting algorithm
		% into account.  *Shrug*
		%
		rand:uniform() * (WgtA + WgtB) < WgtA
	end.


% Parse SRV Rdata into tuples in Erlangy format:
%  [ { priority(),weight(),protocol(),protoport(),hostname() } ]
%
% The protocol is an extension made here in support of
% mixtures of TCP and UDP, for example.  Queries for
% these can be independently made, and the result can
% be input as a single fixed-valued parameter, or one
% input as a list of pairs of protocol and Rdata list.
% 
-spec srvrdata2parsed( protocol(),[binary] ) -> [ srvrecord() ].
%
srvrdata2parsed( Proto,SRV_RdataList ) ->
	ParseOne = fun( SRV_Rdata ) ->
		HostLen = length( SRV_Rdata ) - 6,
		<<Prio:16/big-unsigned-integer,
		   Wgt:16/big-unsigned-integer,
		  Port:16/big-unsigned-integer,
		  Host:HostLen/binary>> = SRV_Rdata,
		{ Prio,Wgt,Proto,Port,bin2dotted( Host ) }
	end,
	lists:map( ParseOne,SRV_RdataList ).


% Given a list of SRV records in wire format, parse and
% sort them and return an Erlangy format:
%  [ { priority(),weight(),protocol(),protoport(),hostname() } ]
%
% The protocol is an extension made here in support of
% mixtures of TCP and UDP, for example.  Queries for
% these can be independently made, and the result can
% be input as a single fixed-valued parameter, or one
% input as a list of pairs of protocol and Rdata list.
% 
-spec srvrdata2sorted( protocol(),[binary] ) -> [ srvrecord() ].
%
srvrdata2sorted( Proto,SRV_RdataList ) ->
	lists:sort( ?LambdaLift2(srvless),
		srvrdata2parsed( Proto,SRV_RdataList )).
%
-spec srvrdata2sorted( [ { protocol(), [binary] } ] ) -> [ srvrecord() ].
%
srvrdata2sorted( SRV_RdataByProto ) ->
	lists:sort( ?LambdaLift2(srvless),
		lists:concat(
			lists:map( ?LambdaLift2(srvrdata2parsed),
			SRV_RdataByProto ))).


% Given a sorted list of Erlangy SRV records, return
% the ports and hosts to try as a list.  Repeated
% entries simply come through, as it would be either
% awkward operational practice or intent (perhaps for
% going beyond a client's fixed timeout, as much as
% that may be a hack).
%
% Order the entries like desired for SRV records.
%
-spec srv2protoport( [ srvrecord() ] ) -> [ { hostname(),protoport(),protocol() } ].
%
srv2protoport( SortedSRVs ) ->
	[ {Hostname,Port,Proto} ||
		{_Prio,_Wgt,Proto,Port,Hostname} <- SortedSRVs ].


% Parse the information in a TLSA record into a tlsarecord() holding
%  { protocol(),protoport(),tlsa_certusage(),tlsa_selector(),tlsa_matchingtype(),binary() }.
% 
% The protocol and port are supplied as fixed parameters to the parser.
%
-spec tlsardata2parsed( protocol(),protoport(),[ binary ] ) -> tlsarecord().
%
tlsardata2parsed( Proto,Port,TLSA_RdataList ) ->
	CrtUseOpts = [ ca_constraint, cert_constraint, ta_assertion, domain_issued_cert ],
	SelOpts = [ full_cert, pubkey ],
	MatchOpts = [ exact, sha256, sha512 ],
	ParseOne = fun( TLSA_Rdata ) ->
		DataLen = length( TLSA_Rdata ) - 3,
		<<CrtUse:8/unsigned-integer,
		     Sel:8/unsigned-integer,
		   Match:8/unsigned-integer,
		    Data:DataLen/binary>> = TLSA_Rdata,
		%TODO:FILTER% Rogue DNS data could crash us...
		%TODO:FILTER% CrtUse < lists:length( CrtUseOpts ),
		%TODO:FILTER% Sel    < lists:length( SelOpts    ),
		%TODO:FILTER% Match  < lists:length( MatchOpts  ) ].
		{ Proto,
		  Port,
		  lists:nth( 1+CrtUse,CrtUseOpts ),
		  lists:nth( 1+Sel,   SelOpts    ),
		  lists:nth( 1+Match,MatchOpts   ),
		  Data }
	end,
	lists:map( ParseOne,TLSA_RdataList ).


