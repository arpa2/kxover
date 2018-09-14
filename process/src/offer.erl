% Support for KX-OFFER messaging and the related key exchange.
%
% From: Rick van Rein <rick@openfortress.nl>


-module( offer ).

-export([
	recv/3,
	send/2,
	kex/2,
	vfy/2
]).


-include_lib( "unbound/include/unbound.hrl" ).
-include_lib( "unbound/include/params.hrl" ).
-include_lib( "perpetuum/include/gen_perpetuum.hrl" ).

-include( "KXOVER.hrl" ).
-include( "RFC5280.hrl" ).
-include( "RFC4120.hrl" ).

-define(LambdaLiftM1(M,F), fun(X  ) -> M:F ( X   ) end).

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
	io:format( "Generating ECDHE on secp256k1 (TODO:FIXED for now)~n" ),
	%TODO%AGREE_ON_ECDH_CURVE_NOT_SINGLE_AND_FIXED% { _MyPubKey,MyPrivKey } = crypto:generate_key( ecdh,ECDHParams ),
	{ MyPubKey,MyPrivKey } = crypto:generate_key( ecdh,secp256k1 ),
	io:format( "Client MyPubKey = ~p~nClient MyPrivKey = ~p~n",[MyPubKey,MyPrivKey] ),
	MidAppState =
		maps:put( kexpub,MyPubKey,
		maps:put( kexpriv,MyPrivKey,
		maps:put( nonce,trunc( rand:uniform() * (1 bsl 32) ),
		maps:put( kvno,123,  %TODO%KVNO%
			AppState )))),
	send( MidAppState ).
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
		Cert#'Certificate'.tbsCertificate#'TBSCertificate'.subjectPublicKeyInfo,
	%
	% Construct key exchange info
	%
	KexAlg = #'AlgorithmIdentifier' {
		algorithm = {1,2,840,10045,2,1},
		parameters = <<6,5,43,129,4,0,10>> },
	KexPubKey = maps:get( kexpub,AppState ),
	KexData = #'SubjectPublicKeyInfo'{ algorithm=KexAlg,subjectPublicKey=KexPubKey },
	%
	% Construct the Authenticator
	%
	Princ = #'PrincipalName' {
		'name-type'   = 2,
		'name-string' = [ "krbtgt", maps:get( srealm,AppState ) ]
	},
	Realm = maps:get( crealm,AppState ),
	%%TODO%% Ugly, ugly calendar time... :'-(
	%%%TODO:TIMES%%% {{NowYear, NowMonth, NowDay}, {NowHour, NowMinute, NowSecond}} = calendar:now_to_datetime( erlang:now() ),
	NowYear=2018,NowMonth=2,NowDay=21,NowHour=11,NowMinute=43,NowSecond=12,
	NowStr = lists:flatten(io_lib:format("~4..0w-~2..0w-~2..0wT~2..0w:~2..0w:~2..0w",[NowYear,NowMonth,NowDay,NowHour,NowMinute,NowSecond])),
	%
	% Construct the KX-TBSDATA record
	%
	TBSdata = #'KX-TBSDATA' {
		'request-time' = NowStr,
		%
		% Key description information:
		'kvno'         = KVNO,
		'kxname'       = Princ,
		'kxrealm'      = Realm,
		'key-exchange' = KexData,
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
	SigVal = public_key:sign( TBSbytes,sha512,Priv ),	%%%TODO:FIXED:HASHALG%%%
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
	io:format( "Generating ECDHE on secp256k1 (TODO:FIXED for now)~n" ),
	%TODO%AGREE_ON_ECDH_CURVE_NOT_AUTOMATICALLY_SAME_AS_SIGNATURE% io:format( "ECDHParams = ~p~n",[ECDHParams] ),
	%TODO%AGREE_ON_ECDH_CURVE_NOT_AUTOMATICALLY_SAME_AS_SIGNATURE% { _MyPubKey,MyPrivKey } = crypto:generate_key( ecdh,ECDHParams ),
	{ MyPubKey,MyPrivKey } = crypto:generate_key( ecdh,secp256k1 ),
	io:format( "Server MyPubKey = ~p~nServer MyPrivKey = ~p~n",[MyPubKey,MyPrivKey] ),
	MidAppState = maps:put( kexpub,MyPubKey,
	              maps:put( kexpriv,MyPrivKey,AppState )),
	KXvfy = maps:get( ckx,AppState ),
	kex( MidAppState,KXvfy,MyPrivKey );
%
kex( client,AppState ) ->
	{ MyPivKey,MidAppState } = maps:take( kexpriv,AppState ),
	KXvfy = maps:get( skx,MidAppState ),
	kex( MidAppState,KXvfy,MyPivKey ).
%
kex( AppState,KXvfy,MyPrivKey ) ->
	KXtbsdata = KXvfy#'KX-OFFER'.'signature-input',
	%TODO%BUG% The PeerPubKey is the same on client and server -- and different from what's generated on both
	#'SubjectPublicKeyInfo'{ algorithm=KXalg,subjectPublicKey=PeerPubKey } =
		KXvfy#'KX-OFFER'.'signature-input'#'KX-TBSDATA'.'key-exchange',
	#'AlgorithmIdentifier'{ algorithm=_AlgOID,parameters=_ECDHParams } =
		KXalg,
	%
	% Compute the standard shared value Z
	%
	%TODO%AGREE_ON_ECDH_CURVE_NOT_AUTOMATICALLY_SAME_AS_SIGNATURE% Z = crypto:compute_key( ecdh,PeerPubKey,MyPrivKey,ECDHParams ),
	io:format( "ecdh/secp256k1.PeerPubKey = ~p~necdh/secp256k1.MyPrivKey = ~p~n",[PeerPubKey,MyPrivKey] ),
	Z = crypto:compute_key( ecdh,PeerPubKey,MyPrivKey,secp256k1 ),
	io:format( "Generated ECDHE on secp256k1 (TODO:FIXED for now)~n" ),
	%TODO% Hash more than Z into the KeyInfo, as in KXOVER-KEY-INFO
	Princ = #'PrincipalName' {
		'name-type'   = 2,
		%%%TODO%%% 'name-string' = [ "krbtgt", maps:get( srealm,AppState ) ]
		'name-string' = [ "krbtgt", <<"ARPA2.NET">> ]
	},
	%%%TODO%%% Realm = maps:get( crealm,AppState ),
	Realm = <<"SURFNET.NL">>,
	KeyInfo = #'KXOVER-KEY-INFO'{
		'kxover-name' = <<"KXOVER">>,
		'seq-nr'      = 1,
		kxname        = Princ,
		kxrealm       = Realm,
		till          = KXtbsdata#'KX-TBSDATA'.till,
		kvno          = KXtbsdata#'KX-TBSDATA'.kvno,
		etype         = 1, %%%TODO:First_Acceptable_etype_or_list_thereof%%%
		'shared-key'  = Z
	},
	{ok,KeyInfoBin} = 'KXOVER':encode( 'KXOVER-KEY-INFO',KeyInfo ),
	%TODO% Following is preliminary redesign based on HMAC with Key=Z
	%TODO% Note the fixed choice of hash, as it is not a security concern (and yet, HMAC?!?)
	%TODO% Repeat with seq-nr for longer SharedKey segments if needed
	%TODO%NAHHH% SharedKey = crypto:hmac( sha512,Z,KeyInfo ),
	SharedKey = crypto:hash( sha512,KeyInfoBin ),
	io:format( "Z = ~p~nKeyInfo = ~p~nSharedKey = ~p~n",[Z,KeyInfo,SharedKey] ),
	%TODO% Compute krbtgt blob
	KrbTgt = krbtgtBlob_TODO,
	NewAppState = maps:put( key,SharedKey,	%TODO% Why? only need MyPubKey...
	              maps:put( krbtgt,KrbTgt,AppState )),
	%DEBUG% io:format( "NewAppState = ~p~n",[NewAppState] ),
	{ noreply,NewAppState }.


% Verify a KX-OFFER signature; return true for succes, or false for failure.
%
% The verification does the following things:
%  1. Check that data fields are acceptable to us
%  2. Check that signature-alg matches certificate alg	%TODO%DROP%FROM%KXOFFER%
%  3. Verify the KX-TBSDATA against the certificate key
%  4. Evaluate the chain of certificates
%  5. Evaluate DANE against the chain of certificates
%
vfy( client,AppState ) ->
	KXoffer = maps:get( skx,AppState ),
	io:format( "client got KXoffer = ~p~n",[KXoffer] ),
	vfy( KXoffer,AppState );
%
vfy( server,AppState ) ->
	KXoffer = maps:get( ckx,AppState ),
	io:format( "server got KXoffer = ~p~n",[KXoffer] ),
	vfy( KXoffer,AppState );
%
vfy( KXoffer,AppState ) ->
	%
	% Analyse the information provided inasfar as it is concerned
	% with digital signing of the KX-OFFER.
	%
	SigAlg = KXoffer#'KX-OFFER'.'signature-alg',   %TODO%DROP%FROM%KXOFFER%
	SigBin = KXoffer#'KX-OFFER'.'signature-value',
	KX_TBS = KXoffer#'KX-OFFER'.'signature-input',
	Owner  = KXoffer#'KX-OFFER'.'signature-owner',
	[ Cert|_ ] = Owner,
	#'SubjectPublicKeyInfo'{ algorithm=AlgId,subjectPublicKey=SubjPubKey } =
		Cert#'Certificate'.tbsCertificate#'TBSCertificate'.subjectPublicKeyInfo,
	AlgOK = (AlgId == SigAlg),			%TODO%DROP%FROM%KXOFFER%
	{_KeyAlg,HashAlg,VerifyPublicKey} = case {AlgOK,AlgId} of
	%TODO% useful cases
	{true,#'AlgorithmIdentifier'{ algorithm={1,2,840,113549,1,1,5}, parameters=asn1_NOVALUE }} ->
		{rsa,sha,SubjPubKey};
	{true,#'AlgorithmIdentifier'{ algorithm={1,2,840,10040,4,3}, parameters=asn1_NOVALUE }} ->
		{dsa,sha,SubjPubKey};
	{true,#'AlgorithmIdentifier'{ algorithm={1,2,840,10045,4,1}, parameters=asn1_NOVALUE }} ->
		%TODO% RFC 3279 allows parameters and/... pass in as ec_public_key()
		ECPubKey = SubjPubKey,	%TODO% More elaborate juggling...
		{ecdsa,sha,ECPubKey};
	_ ->
		{unknown,unknown,unknown}
	end,
	%
	% Validate the signature on the KX-OFFER to be made by the
	% first Certificate in the Owner sequence.
	%
	SigOK = if VerifyPublicKey == unknown ->
		false;
	true ->
		public_key:verify( KX_TBS,HashAlg,SigBin,VerifyPublicKey )
	end,
	%
	% Validate the chain as a signed sequence of at least one Certificate,
	% ending in a self-signed certificate.
	%
	% We read the envvar kxover:root_certs for a file name with a PEM of
	% root certificates to be trusted.  If no such value is provided, then
	% RootCerts ends up as undefined, and no checks will be enforced; if
	% the name is given, it must be readable and RootCerts will be a list
	% of Certificate entries for validation.  An empty list would always
	% fail, and will be carefully distinguished from undefined.
	%
	% The envvar may contain a single file name or a list of file names;
	% each file may hold one or more PEM files with root certificates
	% to be trusted.
	%
	%TODO% We seem to need to load explicitly?!?
	%
	application:load( kxover ),
	RootCerts = case application:get_env( kxover,root_certs ) of
	{ok,RootCertPemFiles} ->
		io:format( "RootCertPemFiles = ~p~n",[RootCertPemFiles] ),
		ReadAll = fun( YF,Files,Accu ) ->
			case Files of
			[] ->
				% nothing more to collect
				Accu;
			[F|FS] ->
				% use an efficient tail call:
				YF( YF,FS,YF( YF,F,Accu ));
			F when is_binary( F ) ->
				% prefix an individual file;
				% retention of entries' order
				{ok,NewText} = file:read_file( F ),
				[ NewText | Accu ]
			end
		end,
		Extract = fun( YF,CrtList ) ->
			case CrtList of
			[ { 'Certificate',DER,not_encrypted } | Rest ] ->
				[ DER | YF( YF,Rest ) ];
			[ _ | Rest ] ->
				YF( YF,Rest );
			[] ->
				[]
			end
		end,
		PemBin = ReadAll( ReadAll,RootCertPemFiles,[] ),
		Extract( Extract,lists:flatten( lists:map( ?LambdaLiftM1( public_key,pem_decode ),PemBin )));
	undefined ->
		undefined
	end,
	io:format( "RootCerts = ~p~n",[RootCerts] ),
	CheckChain = fun( YF,OwnerChain ) ->
		case OwnerChain of
		[EndCert] ->
			{ok,EndCertDER} = 'RFC5280':encode( 'Certificate',EndCert ),
			%DEBUG% io:format( "public_key:pkix_is_self_signed( ~p )~n",[EndCertDER] ),
			SelfSigned = public_key:pkix_is_self_signed( EndCertDER ),
			if not SelfSigned ->
				false;
			RootCerts == undefined ->
				true;
			is_list( RootCerts ) ->
				%DEBUG% io:format( "Testing if ~p in ~p~n",[EndCertDER,RootCerts] ),
				io:format( "End Cert found is ~p~n",[lists:member( EndCertDER,RootCerts )] ),
				lists:member( EndCertDER,RootCerts )
			end;
		[FirstCert|[SecondCert|_]=MoreChain] ->
			{ok, FirstCertDER} = 'RFC5280':encode( 'Certificate', FirstCert ),
			{ok,SecondCertDER} = 'RFC5280':encode( 'Certificate',SecondCert ),
			case public_key:pkix_is_issuer( FirstCertDER,SecondCertDER ) of
			false ->
				false;
			true ->
				YF( YF,MoreChain )
			end
		end
	end,
	ChainOK = CheckChain( CheckChain,Owner ),
	%
	% Validate trust based on DANE.  When root certificates are also taken
	% into account, including for the case of a federation, additionally
	% check the last certificates to be a valid root certificate.
	%
	%TODO% implement! Trust based on optional check on root certificates (if configured)
	%
	CheckDANE = fun( YF,DANE ) ->
		case DANE of
		[] ->
			false;
		[{_,_,CrtUsg,Sel,Mtch,Data}|MoreDANE] ->
			% Cert Usage: Pick a certificate and whether under a PublicCA
			{Used,_PublicCA_TODO_USE} = case CrtUsg of
			ca_constraint ->
				{ lists:last( Owner ),true };
			cert_constraint ->
				{ Cert,true };
			ta_assertion ->
				{ lists:last( Owner ),false };
			domain_issued_cert ->
				{ Cert,false }
			end,
			% Selection: Take the Certificate or SubjectPublicKeyInfo
			{ok,Selection} = case Sel of
			full_cert ->
				'RFC5280':encode( 'Certificate',Used );
			pubkey ->
				% Known formal problem, except in everyday practice:
				% Certificate is BER-encoded, we are re-encoding as DER
				'RFC5280':encode( 'SubjectPublicKeyInfo',
					Used#'Certificate'.tbsCertificate#'TBSCertificate'.subjectPublicKeyInfo)
			end,
			% MatchType: Possibly hash the data before comparison
			Matcher = if Mtch == exact ->
				Selection;
			true ->
				%DEBUG% io:format( "Match = ~p~nSelection = ~p~n",[Mtch,Selection] ),
				crypto:hash ( Mtch,Selection )
			end,
			if Matcher /= Data ->
				YF( YF,MoreDANE );
			true ->
				true
			end
		end
	end,
	TrustOK = CheckDANE( CheckDANE,maps:get( tlsa,AppState )),
	%
	% Pass back the final verdict through the Success or Failure signal
	%
	AllOK = AlgOK and SigOK and ChainOK and TrustOK,
	io:format( "AlgOK=~p, SigOK=~p, ChainOK=~p, TrustOK=~p ==> AllOK=~p~n",[AlgOK,SigOK,ChainOK,TrustOK,AllOK] ),
	AllOK.

