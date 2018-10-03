% KXOVER client module, with hooks focussed on KXOVER application logic.
%
% This module is used as the application callback module from Perpetuum's
% process instance generated into kxover_client.erl
%
% Callbacks are made to the function named action.  Its event data is TODO
%
% From: Rick van Rein <rick@openfortress.nl>


-module( logic_client ).

-export([
	init/4,
	stop/4,
	nop/4,
	pass/4,
	reject/4,
	miscdata/4,
	krbtgtMissing/4,
	dnssec_req_SRV/4,
	got_SRV/4,
	dnssec_req_TLSA/4,
	got_TLSA/4,
	dns_req_A_AAAA/4,
	got_A_AAAA/4,
	send_KX_req/4,
	got_KX_resp/4,
	signature_verify/4,
	signature_error/4,
	ecdhe2krbtgt/4,
	send_krbtgt_to_all_requesters/4,
	all_hooks/0
]).

-include_lib( "unbound/include/unbound.hrl" ).
-include_lib( "unbound/include/params.hrl" ).
%TODO% -include_lib( "perpetuum/include/gen_perpetuum.hrl" ).

-include( "KXOVER.hrl" ).
-include( "RFC5280.hrl" ).
-include( "RFC4120.hrl" ).


-define(LambdaLift2(Atom), fun(X,Y) -> Atom( X,Y ) end).

-define(ifthenelse(I,T,E), if I -> T; true -> E end).


%
% Our internal structure for AppState is a map.
%
% There are entries for DNS answers that have been received:
%   srv     => [ << Pri:16,Wgt:16,Port:16,Host/binary >> ]
%   tlsa    => [ << CertUse:8,Selector:8,MatchTp:8,CertAssocData/binary >> ]
%   aaaa    => [ << IPv6:128 | IPv4:32 >> ]
%
% There are entries for data passing in and out:
%   crealm  => binary	% client realm
%   srealm  => binary	% server realm
%   skx     => binary	% server KX message
%   ckx     => binary	% client KX message
%   krbtgt  => binary	% constructed krbtgt
%   key     => binary	% constructed key
%
% For DNS or DNSSEC, the map holds {unbound,QueryId} => {dns,   Succes,Failure}
% For forced DNSSEC, the map holds {unbound,QueryId} => {dnssec,Succes,Failure}
%


% Remove keys as listed from the AppState and return the result.
% Non-existent keys are silently ignored.
%
drop_state( KeysToGo,AppState ) ->
	lists:foldl( ?LambdaLift2(maps:remove),AppState,KeysToGo ).



% Transition hook: Initialise a new instance.
%
% EventData is the new Petri Net and can be safely ignored.
% Must return {noreply,InitialAppState}
%
init( {},'$init',_PetriNet,{} ) ->
	InitialAppState = #{},
	{ noreply,InitialAppState }.


% Transition hook: Attempt to stop this instance.
%
% EventData holds a Reason.  Return error, delay or (no)reply.
% We gently accept, but first inform our helpers that we are
% not going to be around.
%
stop( {},'$stop',_Reason,AppState ) ->
	NewAppState = dns:cleanup_ub( AppState ),
	{ noreply,NewAppState }.


% Transition hook: No Operation.
%
% This does not act, assuming that the interaction is handled in the
% application running on top of the Perpetuum layer.
%
% EventData is ignored
%
nop( {},_TransName,_EventData,AppState ) ->
	{ noreply,AppState }.


% Transition hook: Pass error in EventData as response code.
%
% This does not act, assuming that the interaction is handled in the
% application running on top of the Perpetuum layer.
%
% EventData is ignored
%
pass( {},_TransName,{error,_}=Error,_AppState ) ->
	Error.


% Transition hook: Report an unknown/unacceptable transition name.
%
% This does not act, assuming that the interaction is handled in the
% application running on top of the Perpetuum layer.
%
% EventData is ignored
%
reject( {},TransName,_EventData,_AppState ) ->
	{ error,TransName }.



% Transition hook: Notice a missing krbtgt/SERVER.REALM@CLIENT.REALM
%
% This starts up the process of looking up a key to use.
%
% Arguments are request and three callbacks of which to trigger one:
%  - Initial request in the form of a TGS-REQ
%  - GotOneFresh
%  - GotOneDawning
%  - GotNone
%
% EventData holds a decrypted and decoded TGS-REQ with at least
%  - cname is krbtgt/SERVER.REALM [remote realm to connect to]
%  - realm is CLIENT.REALM        [local realm]
%  - till is a requested end time (can safely be ignored here)
%  - nonce may be used as a link to outgoing KXOVER requests
%  - etype is the sequence of acceptable encryption types
%
% The hook returns noreply.
%
krbtgtMissing( {},krbtgtMissing,{TGSreq,GotOneFresh,GotOneDawning,GotNone}=_EventData,AppState ) ->
	#'PrincipalName' {
		'name-string' = [ <<"krbtgt">>, ServerRealm ]
	          } = TGSreq#'KDC-REQ'.'req-body'#'KDC-REQ-BODY'.sname,
	ClientRealm = TGSreq#'KDC-REQ'.'req-body'#'KDC-REQ-BODY'.realm,
	NewAppState =	maps:put( crealm,ClientRealm,
			maps:put( srealm,ServerRealm,
			maps:put( tgsreq,TGSreq,
			AppState ))),
	%TODO% Derive GotOne and NeedRefresh from AppState
	False = fun() -> false end,
	GotOne = False (),
	NeedRefresh = False (),
	gen_perpetuum:signal(
		self(),
		?ifthenelse(
			GotOne,
			?ifthenelse(
				NeedRefresh,
				GotOneDawning,
				GotOneFresh),
			GotNone ),
		noreply ),
	{ noreply,NewAppState }.


% Transition hook: Request an SRV record with DNSSEC protection.
%
% We query only the TCP portion, so _kerberos._tcp.
%
% EventData holds { Success,Failure }
%
dnssec_req_SRV( {},dnssec_req_SRV,{Success,Failure}=_EventData,AppState ) ->
	_SRealm = maps:get( srealm,AppState ),
	Domain = <<"_kerberos._udp.stanford.edu">>, %Domain = << "_kerberos._tcp.",SRealm >>,
	Query = #ub_question{ name=Domain, type=?UB_TY_SRV, class=?UB_CL_IN },
	dns:query_ub( dnssec,Query,Success,Failure,AppState ).


% Transition hook: Received an SRV record.
%
% EventData holds the [ WireData::binary() ].
%
% The SRV records need not be sorted for the
% KXOVER server logic, so we simply pass it
% through dns:srvrdata2parsed().
%
got_SRV( {},got_SRV,{ok,WireData},AppState ) ->
	OlderSRV = maps:get( srv,AppState,[] ),
	Protocol = tcp,
	AddedSRV = dns:srvrdata2parsed( Protocol,WireData ),
	NewerSRV = OlderSRV ++ AddedSRV,
	io:format( "NewerSRV is ~p~n",[NewerSRV] ),
	NewAppState = maps:put( srv,NewerSRV,AppState ),
	{ noreply,NewAppState }.


% Transition hook: Request a TLSA record with DNSSEC protection.
%
% EventData holds { Success,Failure,Domain }
%
%TODONOW% Construct request from port and protocol in SRV
%TODO% Query multiple
%TODO% Prepare for collection of responses
%
dnssec_req_TLSA( {},dnssec_req_TLSA,{Success,Failure,Domain}=_EventData,AppState ) ->
	Query = #ub_question{ name=Domain, type=?UB_TY_TLSA, class=?UB_CL_IN },
	dns:query_ub( dnssec,Query,Success,Failure,AppState ).


% Transition hook: Received a TLSA record.
%
% EventData holds the [ WireData::binary() ].
%
got_TLSA( {},got_TLSA,{ok,WireData},AppState ) ->
	OlderTLSA = maps:get( tlsa,AppState,[] ),
	Protocol = Port = dontcare,
	AddedTLSA = dns:tlsardata2parsed (Protocol,Port,WireData),
	NewerTLSA = OlderTLSA ++ AddedTLSA,
	io:format( "NewerTLSA is ~p~n",[NewerTLSA] ),
	NewAppState = maps:put( tlsa,NewerTLSA,AppState ),
	{ noreply,NewAppState }.


% Transition hook: Request A and AAAA records without DNSSEC protection.
%
% EventData holds { Success,Failure,Domain }
%
% This would be very complex, juggling the variations of both IPv4/IPv6
% and the various host names and their ports.  Erlang however, will
% happily connect to a named host and we have no need for DNSSEC at this
% point, so we can rely on Erlang to do this for us.  Pfew!
%
dns_req_A_AAAA( {},dns_req_A_AAAA,{Success,_Failure,_Domain}=_EventData,AppState ) ->
	gen_perpetuum:signal( self(),Success,noreply ),
	{ noreply,AppState }.


% Transition hook: Received an A or AAAA record.
%
% The importance of this function is anihiliated by the
% ability in Erlang to connect to a named host, see
% dns_req_A_AAAA/4 for details.
%
got_A_AAAA( {},got_A_AAAA,_EventData,AppState ) ->
	{ noreply,AppState }.


% Transition hook: Construct a KX request to send.
%
% This event constructs a KX-OFFER and replies it to
% the caller for submission to a KX server.  Note that
% this differs from what the name suggest, namely that
% a KX request will be sent by the logic module.
%
send_KX_req( {},send_KX_req,_EventData,AppState ) ->
	offer:send( client,AppState ).

% Transition hook: Receive a KX response.
%
% This event takes in a KX-OFFER as replied to the caller
% by a KX server which was sent a KX request.  The actual
% reception is not done in the logic module, even when the
% name of this event sounds like it might.
%
got_KX_resp( {},got_KX_resp,KXbin=_EventData,AppState ) ->
	{ok,KXoffer} = 'KXOVER':decode( 'KX-OFFER',KXbin ),
	#'PrincipalName' {
		'name-type'   = 2,
		'name-string' = ["krbtgt",SrvRlm]
	} = KXoffer#'KX-OFFER'.'signature-input'#'KX-TBSDATA'.kxname,
	CliRlm = KXoffer#'KX-OFFER'.'signature-input'#'KX-TBSDATA'.kxrealm,
	ServerRealm = binary:list_to_bin( SrvRlm ),
	ClientRealm = binary:list_to_bin( CliRlm ),
	io:format( "Server responded KX for krbtgt/~p@~p~n",[ ServerRealm,ClientRealm ] ),
	io:format( "Client expects   KX for krbtgt/~p@~p~n",[
		maps:get( srealm,AppState ),
		maps:get( crealm,AppState ) ]),
	ServerRealm = maps:get( srealm,AppState ),
	ClientRealm = maps:get( crealm,AppState ),
	io:format( "KX-OFFER is ~p~n",[KXoffer] ),
	offer:recv( client,AppState,KXoffer ).


% Transition hook: Signature verification request.
%
% EventData holds {Success,Failure}.
%
% The verification does the following things:
%  1. Check that data fields are acceptable to us
%  2. Check that signature-alg matches certificate alg
%  3. Verify the KX-TBSDATA against the certificate key
%  4. Evaluate the chain of certificates
%  5. Evaluate DANE against the chain of certificates
%
signature_verify( {},signature_verify,{Success,Failure},AppState ) ->
	AllOK = offer:vfy( client,AppState ),
	gen_perpetuum:signal( self(),?ifthenelse( AllOK,Success,Failure ),noreply ),
	{ noreply,AppState }.


% Transition hook: Signature verification failed, drop most state.
%
% EventData holds nothing.
%
signature_error( {},signature_error,_EventData,AppState ) ->
	NewAppState = drop_state( [skx],AppState ),
	{ noreply,NewAppState }.


% Transition hook: ECDHE computation, derive shared key and krbtgt.
%
% EventData holds nothing.
%
% This local computation generates a private key and immediately
% forgets about it, after having derived the session key.  The
% public key is passed back to the client, but only after the
% server has stored the krbtgt based on the shared key.
%
% The name is actually a misnomer; we don't actually construct
% a krbtgt; rather, we store the information from which a KDC can
% construct one, with the key data and times for renewal rolling
% and expiration.
%
%TODO% Future crypto uses other names; likely to be post-quantum.
%
ecdhe2krbtgt( {},ecdhe2krbtgt,_EventData,AppState ) ->
	offer:kex( client,AppState ).

% Transition hook: Send constructed krbtgt to all requesters.
%
% EventData holds nothing.
%
send_krbtgt_to_all_requesters( {},send_krbtgt_to_all_requesters,_EventData,AppState ) ->
	%%TODO%% Actually send something
	NewAppState = AppState,
	{ noreply,NewAppState }.

% MiscData hook: The process received asynchronous non-Perpetuum data.
%
% Callbacks from Unbound look like #ub_callback{}
%
miscdata( {},'$miscdata',#ub_callback{}=Reply,AppState ) ->
	dns:miscdata_ub( Reply,AppState )
.
%miscdata( ... )


% Transition hook for all at once: Map for gen_perpetuum:trans_switch/4.
%
% We report all known callbacks; any unknown ones will raise an error.
%
all_hooks() -> #{
	'$init'				=> {logic_client,init,{}},
	'$stop'				=> {logic_client,stop,{}},
	krbtgtMissing			=> {logic_client,krbtgtMissing,{}},
	have_krbtgt			=> {logic_client,have_krbtgt,{}},
	have_dawn_krbtgt		=> {logic_client,have_dawn_krbtgt,{}},
	need_SRV			=> {logic_client,nop,{}},
	dnssec_req_SRV			=> {logic_client,dnssec_req_SRV,{}},
	failed_SRV			=> {logic_client,pass,{}},
	got_SRV				=> {logic_client,got_SRV,{}},
	dnssec_req_TLSA			=> {logic_client,dnssec_req_TLSA,{}},
	failed_TLSA			=> {logic_client,pass,{}},
	got_TLSA			=> {logic_client,got_TLSA,{}},
	dns_req_A_AAAA			=> {logic_client,dns_req_A_AAAA,{}},
	failed_A_AAAA			=> {logic_client,pass,{}},
	got_A_AAAA			=> {logic_client,got_A_AAAA,{}},
	send_KX_req			=> {logic_client,send_KX_req,{}},
	failed_KX			=> {logic_client,nop,{}},
	got_KX_resp			=> {logic_client,got_KX_resp,{}},
	signature_verify		=> {logic_client,signature_verify,{}},
	signature_error			=> {logic_client,signature_error,{}},
	signature_good			=> {logic_client,nop,{}},
	ecdhe2krbtgt			=> {logic_client,ecdhe2krbtgt,{}},
	store_krbtgt_kdb		=> {logic_client,nop,{}},
	send_krbtgt_to_all_requesters	=> {logic_client,send_krbtgt_to_all_requesters,{}},
	successfulEnd			=> {logic_client,nop,{}},
	'$default'			=> {logic_client,reject,{}},
	'$miscdata'			=> {logic_client,miscdata,{}}
%SERVER% 	expiration_timer	=> {logic_client,nop,{}},
%SERVER% 	remove_shortest		=> {logic_client,nop,{}},
%SERVER% 	successfulEnd		=> {logic_client,nop,{}},
%SERVER% 	send_KX_failed		=> {logic_client,nop,{}},
%SERVER% 	cache_exp_timer		=> {logic_client,nop,{}},
}.


