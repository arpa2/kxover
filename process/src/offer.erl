% Support for KX-OFFER messaging and the related key exchange.
%
% From: Rick van Rein <rick@openfortress.nl>


-module( offer ).

-export([
	recv/3,
	send/2,
	kex/2
]).


-include_lib( "unbound/include/unbound.hrl" ).
-include_lib( "unbound/include/params.hrl" ).
%TODO% -include_lib( "perpetuum/include/gen_perpetuum.hrl" ).

-include( "KXOVER.hrl" ).
-include( "RFC5280.hrl" ).
-include( "RFC4120.hrl" ).

-define(ifthenelse(I,T,E), if I -> T; true -> E end).


% Receive an incoming KX frame.  Do this for Role set to either
% client or server, to accommodate for variations in how variables
% move in and out of the function.
%
% The output is a NewAppState holding the stored KX-OFFER in the
% proper field, so either ckx or skx.
%
recv( server,AppState,KXoffer ) ->
	%TODO% Match KXalg/etc... against willingness (and prep2send)
	NewAppState = maps:put( ckx,KXoffer,AppState ),
	{ noreply,NewAppState };
%
recv( client,AppState,KXoffer ) ->
	%TODO% Lots more processing possible
	%TODO% Match KXalg/etc... against willingness (as sent)
	NewAppState = maps:put( skx,KXoffer,AppState ),
	{ noreply,NewAppState }.


% Construct the KX response frame.  Do this for Role set to either
% client or server, to accommodate for variations in how variables
% move in and out of the function.
%
% This output is a #'KX-OFFER' record that can be used to message
% to the remote peer.  It is returned as {reply,KXoffer,NewAppState}s
% or, TODO:IFANY in case of error, as {error,Reason}.
%
% The process flow should have ensured support for the corresponding
% krbtgt/SERVER.REALM@CLIENT.REALM and kvno/etype/... combination.
%
% The AppState for skx is also written by this procedure [do we need it?]
%
send( server,AppState ) ->
	KXcli = maps:get( ckx,AppState ),
	Nonce = KXcli#'KX-OFFER'.nonce,
	KVNO  = KXcli#'KX-OFFER'.'signature-input'#'KX-TBSDATA'.kvno,
	MidAppState =
		maps:put( nonce,Nonce,
		maps:put( kvno,KVNO,
		maps:put( crealm,<<"ARPA2.NET">>,
		maps:put( srealm,<<"SURFNET.NL">>,
			AppState )))),
	send( MidAppState );
%
send( client,AppState ) ->
	send( AppState ).
%
send( AppState ) ->
	Nonce = maps:get( nonce,AppState ),
	KVNO = maps:get( kvno,AppState ),
	%
	% Reconstruct certificate and key info
	%
	{ok,CertDER} = file:read_file( "selfsig-cert.der" ),
	{ok,Cert} = 'RFC5280':decode( 'Certificate',CertDER ),
	{ok,PrivDER} = file:read_file( "selfsig-key.der" ),
	io:format( "PrivDER = ~p~n",[PrivDER] ),
	Priv = public_key:der_decode( 'ECPrivateKey',PrivDER ),
	io:format( "Priv = ~p~n",[Priv] ),
	#'SubjectPublicKeyInfo'{ algorithm=SigAlg,subjectPublicKey=_SubjPubKey } =
		PubKeyInfo =
		Cert#'Certificate'.tbsCertificate#'TBSCertificate'.subjectPublicKeyInfo,
	%
	% Construct the Authenticator
	%
	Princ = #'PrincipalName' {
		'name-type'   = 2,
		'name-string' = [ "krbtgt", maps:get( srealm,AppState ) ]
	},
	Realm = maps:get( crealm,AppState ),
	%%TODO%% Ugly, ugly calendar time... :'-(
	Now = erlang:system_time( microsecond ),
	%NowSec  = Now div 1000000,
	NowUSec = Now rem 1000000,
	%%%TODO:TIMES%%% {{NowYear, NowMonth, NowDay}, {NowHour, NowMinute, NowSecond}} = calendar:now_to_datetime( erlang:now() ),
	NowYear=2018,NowMonth=2,NowDay=21,NowHour=11,NowMinute=43,NowSecond=12,
	NowStr = lists:flatten(io_lib:format("~4..0w-~2..0w-~2..0wT~2..0w:~2..0w:~2..0w",[NowYear,NowMonth,NowDay,NowHour,NowMinute,NowSecond])),
	Author = #'Authenticator' {
		% OPTIONAL fields not used
		% crealm/cname ignored, set to anything
		'authenticator-vno' = 5,
		'crealm'            = Realm,
		'cname'             = Princ,
		'cusec'             = NowUSec,
		'ctime'             = NowStr
	},
	%
	% Construct the KX-TBSDATA record
	%
	TBSdata = #'KX-TBSDATA' {
		'authenticator'= Author,
		%
		% Key description information:
		'kvno'         = KVNO,
		'kxname'       = Princ,
		'kxrealm'      = Realm,
		'key-exchange' = PubKeyInfo,  %TODO% KEXdata
		%
		% Timing information:
		%ERROR% 'till' = (Now rem 10000000) + 86400 * 32,
		'till' = NowStr,
		%
		% Negotiation terms, each in preference order:
		'accept-etype'  = []
		%OPTIONAL% 'accept-group'  = [],
		%OPTIONAL% 'accept-sigalg' = [],
		%OPTIONAL% 'accept-ca'     = []
	},
	{ok,TBSbytes} = 'KXOVER':encode( 'KX-TBSDATA',TBSdata ),
	SigVal = public_key:sign( TBSbytes,sha256,Priv ),	%%%TODO:FIXED:HASHALG%%%
	%
	% Construct the KX-OFFER record
	%
	ServerKX = #'KX-OFFER' {
		%
		% Transport-level information:
		'nonce' = Nonce,
		%
		% About the signature:
		'signature-input' = TBSdata,
		'signature-owner' = [ Cert ],
		%
		%  The actual signature:
		'signature-alg'   = SigAlg,
		'signature-value' = SigVal
	},
	NewAppState = maps:put( skx,ServerKX,AppState ),
	{ reply,ServerKX,NewAppState }.


% Perform the computations to derive shared key for the krbtgt.
%
% The Role is either set to client or server, to capture the
% necessary variations in key pair generation order.
%
% This server computation generates a private key and immediately
% forgets about it, after having derived the session key.  The
% public key is passed back to the client, but only after the
% server has stored the krbtgt based on the shared key.  The
% client computation however, generates the key pair and sends
% the public key; it retains the private key during a KX-OFFER
% exchange with the server before it can drop the private key.
%
% Parameters, such as the key exchange algorithm and etypes,
% are negotiated as part of send/recv functions, so they are
% assumed correct when processing arrives here.
%
% The function returns {noreply,NewAppState} where it will have
% setup the key and TODO:krbtgt values in the NewAppState, or,
% TODO:IFANY in case, of error, it returns {error,Reason}.
%
kex( server,AppState ) ->
	KXvfy = maps:get( ckx,AppState ),
	io:format( "Generating ECDHE on secp192r1 (TODO:FIXED for now)~n" ),
	%TODO%AGREE_ON_ECDH_CURVE_NOT_AUTOMATICALLY_SAME_AS_SIGNATURE% io:format( "ECDHParams = ~p~n",[ECDHParams] ),
	%TODO%AGREE_ON_ECDH_CURVE_NOT_AUTOMATICALLY_SAME_AS_SIGNATURE% { _MyPubKey,MyPrivKey } = crypto:generate_key( ecdh,ECDHParams ),
	{ MyPubKey,MyPrivKey } = crypto:generate_key( ecdh,secp192r1 ),
	io:format( "MyPrivKey = ~p~nMyPubKey = ~p~n",[MyPrivKey,MyPubKey] ),
	kex( AppState,KXvfy,MyPrivKey );
%
kex( client,AppState ) ->
	KXvfy = maps:get( skx,AppState ),
	MyPivKey = fetch_MyPrivKey_TODO,
	kex( AppState,KXvfy,MyPivKey ).
%
kex( AppState,KXvfy,MyPrivKey ) ->
	KXtbsdata = KXvfy#'KX-OFFER'.'signature-input',
	#'SubjectPublicKeyInfo'{ algorithm=KXalg,subjectPublicKey=PeerPubKey } =
		KXvfy#'KX-OFFER'.'signature-input'#'KX-TBSDATA'.'key-exchange',
	#'AlgorithmIdentifier'{ algorithm=_AlgOID,parameters=_ECDHParams } =
		KXalg,
	%
	% Compute the standard shared value Z
	%
	%TODO%AGREE_ON_ECDH_CURVE_NOT_AUTOMATICALLY_SAME_AS_SIGNATURE% Z = crypto:compute_key( ecdh,PeerPubKey,MyPrivKey,ECDHParams ),
	Z = crypto:compute_key( ecdh,PeerPubKey,MyPrivKey,secp192r1 ),
	io:format( "Generated ECDHE on secp192r1 (TODO:FIXED for now)~n" ),
	%TODO% Hash more than Z into the KeyInfo, as in KXOVER-KEY-INFO
	KeyInfo = #'KXOVER-KEY-INFO'{
		'kxover-name' = <<"KXOVER">>,
		'seq-nr'      = 1,
		kxname        = KXtbsdata#'KX-TBSDATA'.kxname,
		kxrealm       = KXtbsdata#'KX-TBSDATA'.kxrealm,
		till          = KXtbsdata#'KX-TBSDATA'.till,
		kvno          = KXtbsdata#'KX-TBSDATA'.kvno,
		etype         = 1, %%%TODO:First_Acceptable_etype_or_list_thereof%%%
		'shared-key'  = Z
	},
	{ok,KeyInfoBin} = 'KXOVER':encode( 'KXOVER-KEY-INFO',KeyInfo ),
	%TODO% Following is preliminary redesign based on HMAC with Key=Z
	%TODO% Note the fixed choice of hash, as it is not a security concern (and yet, HMAC?!?)
	%TODO% Repeat with seq-nr for longer SharedKey segments if needed
	%TODO%NAHHH% SharedKey = crypto:hmac( sha256,Z,KeyInfo ),
	SharedKey = crypto:hash( sha256,KeyInfoBin ),
	io:format( "Z = ~p~nKeyInfo = ~p~nSharedKey = ~p~n",[Z,KeyInfo,SharedKey] ),
	%TODO% Compute krbtgt blob
	KrbTgt = krbtgtBlob_TODO,
	NewAppState = maps:put( key,SharedKey,	%TODO% Why? only need MyPubKey...
	              maps:put( krbtgt,KrbTgt,AppState )),
	%DEBUG% io:format( "NewAppState = ~p~n",[NewAppState] ),
	{ noreply,NewAppState }.

