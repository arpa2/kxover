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
	tlsardata2parsed/3,
	query_ub/5,
	miscdata_ub/2,
	cleanup_ub/1
]).

-include_lib( "unbound/include/unbound.hrl" ).
-include_lib( "unbound/include/params.hrl" ).

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
bin2dotted( WireName ) ->
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
		HostLen = size( SRV_Rdata ) - 6,
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
		DataLen = size( TLSA_Rdata ) - 3,
		if DataLen =< 0 ->
			false;
		true ->
			<<CrtUse:8/unsigned-integer,
			     Sel:8/unsigned-integer,
			   Match:8/unsigned-integer,
			    Data:DataLen/binary>> = TLSA_Rdata,
			OK1 = Sel    < length( SelOpts    ),
			OK2 = CrtUse < length( CrtUseOpts ),
			OK3 = Match  < length( MatchOpts  ),
			if OK1 and OK2 and OK3 ->
				{ true,
					{ Proto,
					  Port,
					  lists:nth( 1+CrtUse,CrtUseOpts ),
					  lists:nth( 1+Sel,   SelOpts    ),
					  lists:nth( 1+Match,MatchOpts   ),
					  Data } };
			true ->
				false
			end
		end
	end,
	lists:filtermap( ParseOne,TLSA_RdataList ).


% Send a query to Unbound for background handling, and delivery
% through the '$miscdata' callback from gen_perpetuum.
%
% Quality is set to either dns or dnssec.  Success and Failure
% are callback signals to be sent when handling the outcome.
%
% The routine processes AppState for client or server and returns
% a proper return value for a callback from gen_perpetuum.
%
query_ub( Quality,#ub_question{}=Query,Success,Failure,AppState ) when (Quality==dns) or (Quality==dnssec) ->
	case unbound:resolve( Query ) of
	{ ok,QueryId } ->
		NewAppState = maps:put( {unbound,QueryId},{Quality,Query,Success,Failure},AppState ),
		{ noreply,NewAppState };
	{ error,_ }=Error ->
		% We do not trigger Failure because that would be a transition
		% after this one, and this one is even failing.  So, we use the
		% Perpetuum option of returning an {error,Reason}
		Error
	end.


% Handle gen_perpetuum's callback '$miscdata', though it has already
% been simplified to hold a #ub_callback{} and is further supplied
% with AppState.  The routine handles the AppState for client or
% server in the same manner.
%
miscdata_ub( #ub_callback{ref=Ref,result=Result}=Reply,AppState ) ->
	% Ref = Reply#ub_callback.ref,
	% Result = Reply#ub_callback.result,
	{Entry,NewAppState} = maps:take( {unbound,Ref},AppState ),
	io:format( "$miscdata uses DNS entry ~p~n",[Entry] ),
	case Entry of
	{ Tag,Query,Success,Failure } when (Tag==dns) or (Tag==dnssec) ->
		if Reply#ub_callback.error ->
			%DEBUG% io:format( "Technicalities got in the way~n" ),
			gen_perpetuum:signal( self(),Failure,Reply#ub_callback.error );
		Query /= Result#ub_result.question ->
			%DEBUG% io:format( "Not my question~n" ),
			gen_perpetuum:signal( self(),Failure,{error,mismatch} );
		not Result#ub_result.havedata ->
			%DEBUG% io:format( "No data, no reply~n" ),
			gen_perpetuum:signal( self(),Failure,{error,nodata} );
		(Tag==dnssec) and not Result#ub_result.secure ->
			%DEBUG% io:format( "Should have been secure~n" ),
			gen_perpetuum:signal( self(),Failure,{error,insecure} );
		Result#ub_result.bogus ->
			%DEBUG% io:format( "Bogus response~n" ),
			gen_perpetuum:signal( self(),Failure,{error,{bogus,Result#ub_result.why_bogus}} );
		Result#ub_result.nxdomain ->
			%DEBUG% io:format( "Domain does not exist~n" ),
			gen_perpetuum:signal( self(),Failure,{error,nxdomain} );
		true ->
			%DEBUG% io:format( "Yay, a proper result!  Signal both me and my parent~n" ),
			gen_perpetuum:signal( self(),Success,{ok,Result#ub_result.data} )
		end,
		{noreply,NewAppState};
	% The following has been changed to an exception with maps:take/2 instead of maps:get( _,_,{} )
	{} ->
		{error,no_such_query}
	end.


% Cleanup any outstanding Unbound requests from the AppState.
%
% Avoid race conditions from unprocessed Unbound responses by
% removing them after their cancellation.  Cancellation with
% Unbound may fail after delivery, but we ignore that.  After
% cancellation we are certain that no new responses can arrive.
%
% The AppState may be for client or server.  The function
% returns a new AppState value.
%
cleanup_ub( AppState ) ->
	Cleanup = fun( Key,_Val ) ->
		case Key of
		{unbound,QueryId} ->
			% Cancel, then remove from AppState
			unbound:cancel( QueryId ),
			false;
		_ ->
			% Keep data where it is
			true
		end
	end,
	RemoveUB = fun( YF ) ->
		receive
		#ub_callback{}=_Response ->
			% ignore _Response and try another
			YF( YF )
		after 0 ->
			ok
		end
	end,
	NewAppState = maps:filter( Cleanup,AppState ),
	RemoveUB( RemoveUB ),
	NewAppState.


