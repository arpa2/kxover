% KXOVER server module, with hooks focussed on KXOVER application logic.
%
% This module is used as the application callback module from Perpetuum's
% process instance generated into kxover_server.erl
%
% Callbacks are made to the function named action.  Its EventData depends
% on the target.  A protocol used when a split can occur is to provide
% a {Success,Failure} pair of transition names, and assume that this code
% will, at some point, send a signal to one of the two, again with some
% EventData that makes sense.  Externals triggers may also happen, and
% should then ben dealt with.
%
% From: Rick van Rein <rick@openfortress.nl>


-module( logic_server ).

-export([
	init/4,
	stop/4,
	nop/4,
	pass/4,
	reject/4,
	miscdata/4,
	recv_KX_req/4,
	dnssec_req_SRV/4,
	got_SRV/4,
	dnssec_req_TLSA/4,
	got_TLSA/4,
	signature_verify/4,
	signature_error/4,
	ecdhe2krbtgt/4,
	send_KX_resp/4,
	all_hooks/0
]).


-include_lib( "unbound/include/unbound.hrl" ).
-include_lib( "unbound/include/params.hrl" ).
%TODO% -include_lib( "perpetuum/include/gen_perpetuum.hrl" ).

-include( "KXOVER.hrl" ).
-include( "RFC5280.hrl" ).
-include( "RFC4120.hrl" ).


-define(LambdaLiftM1(M,F), fun(X  ) -> M:F ( X   ) end).
-define(LambdaLift1(Atom), fun(X  ) -> Atom( X   ) end).
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


% Transition hook: Receive KX request.
%
% This is not initialisation; for that, we have init/4 setup.
%
% EventData holds TODO: binary KX-OFFER
%
recv_KX_req( {},recv_KX_req,KXbin=_EventData,AppState ) ->
	{ok,KXoffer} = 'KXOVER':decode( 'KX-OFFER',KXbin ),
	io:format( "KX-OFFER is ~p~n",[KXoffer] ),
	offer:recv( server,AppState,KXoffer ).


% Transition hook: Request an SRV record with DNSSEC protection.
%
% EventData holds { Success,Failure,Domain }
%
%TODO% Construct request from realm name in KX
%TODO% Query UDP and TCP
%TODO% Prepare for collection of responses
%
dnssec_req_SRV( {},dnssec_req_SRV,{Success,Failure,Domain}=_EventData,AppState ) ->
	Query = #ub_question{ name=Domain, type=?UB_TY_SRV, class=?UB_CL_IN },
	dns:query_ub( dnssec,Query,Success,Failure,AppState).


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
%TODO% Construct request from port and protocol in SRV
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


% Transition hook: Signature verification request.
%
% EventData holds {Success,Failure}.
%
% The verification does the following things:
%  1. Check that data fields are acceptable to us
%  2. Check that signature-alg matches certificate alg	%TODO%DROP%FROM%KXOFFER%
%  3. Verify the KX-TBSDATA against the certificate key
%  4. Evaluate the chain of certificates
%  5. Evaluate DANE against the chain of certificates
%
signature_verify( {},signature_verify,{Success,Failure},AppState ) ->
	AllOK = offer:vfy( server,AppState ),
	gen_perpetuum:signal( self(),?ifthenelse( AllOK,Success,Failure ),noreply ),
	{ noreply,AppState }.


% Transition hook: Signature verification failed, drop most state.
%
% EventData holds nothing.
%
signature_error( {},signature_error,_EventData,AppState ) ->
	NewAppState = drop_state( [ckx],AppState ),
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
	offer:kex( server,AppState ).


% Transition hook: Construct the KX response frame.
%
% EventData holds nothing.  There is a {reply,ReplyKX} to the caller.
%
% This function constructs the #'KX-OFFER' record that can be used
% to respond to the requester.  It is passed back as {reply,KXoffer}.
% The process flow should have ensured support for the corresponding
% krbtgt/SERVER.REALM@CLIENT.REALM and kvno/etype/... combination.
%
% The AppState for skx is also written by this procedure [do we need it?]
%
send_KX_resp( {},send_KX_resp,_EventData,AppState ) ->
	offer:send( server,AppState ).


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
	'$init'			=> {logic_server,init,{}},
	'$stop'			=> {logic_server,stop,{}},
	recv_KX_req		=> {logic_server,recv_KX_req,{}},
	dnssec_req_SRV		=> {logic_server,dnssec_req_SRV,{}},
	failed_SRV		=> {logic_server,pass,{}},
	got_SRV			=> {logic_server,got_SRV,{}},
	dnssec_req_TLSA		=> {logic_server,dnssec_req_TLSA,{}},
	failed_TLSA		=> {logic_server,pass,{}},
	got_TLSA		=> {logic_server,got_TLSA,{}},
	signature_verify	=> {logic_server,signature_verify,{}},
	signature_error		=> {logic_server,signature_error,{}},
	signature_good		=> {logic_server,nop,{}},
	ecdhe2krbtgt		=> {logic_server,ecdhe2krbtgt,{}},
	store_krbtgt_kdb	=> {logic_server,nop,{}},
	send_KX_resp		=> {logic_server,send_KX_resp,{}},
	expiration_timer	=> {logic_server,nop,{}},
	remove_shortest		=> {logic_server,nop,{}},
	successfulEnd		=> {logic_server,nop,{}},
	send_KX_failed		=> {logic_server,nop,{}},
	cache_exp_timer		=> {logic_server,nop,{}},
	'$default'		=> {logic_server,reject,{}},
	'$miscdata'		=> {logic_server,miscdata,{}}
}.


