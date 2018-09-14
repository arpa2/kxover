#!/usr/bin/env escript
%
% Create a KX-OFFER message.
%
% From: Rick van Rein <rick@openfortress.nl>


-include_lib( "kxover/include/RFC4120.hrl" ).
-include_lib( "kxover/include/RFC5280.hrl" ).
-include_lib( "kxover/include/KXOVER.hrl" ).


main (_Argh) ->

	Princ = #'PrincipalName' {
		'name-type'   = 2,
		'name-string' = [ <<"krbtgt">>, <<"ARPA2.ORG">> ]
	},

	Realm = <<"SURFNET.NL">>,

	%%TODO%% Ugly, ugly calendar time... :'-(
	{{NowYear, NowMonth, NowDay}, {NowHour, NowMinute, NowSecond}} = calendar:now_to_datetime( erlang:now() ),
	NowStr = lists:flatten(io_lib:format("~4..0w-~2..0w-~2..0wT~2..0w:~2..0w:~2..0w",[NowYear,NowMonth,NowDay,NowHour,NowMinute,NowSecond])),

	KVNO = 123,

	%TODO% Get a real Signature Algorithm OID in here (but who defines them?)
	SigAlg_OLD = #'AlgorithmIdentifier' {
		algorithm = { 1,2,840,113549,1,1,1 },
		parameters = <<5,0>> },
	SigAlg = #'AlgorithmIdentifier' {
		algorithm = {1,2,840,10045,2,1},
		parameters = <<6,5,43,129,4,0,10>> },
	PubKey_OLD = <<0:1,1:1,0:1,1:1,1:1>>,
	%OLD% PubKey = <<4,205,3,102,67,82,53,171,60,251,102,71,179,236,170,16,4,211,75,
        %OLD%       113,103,248,249,244,204,247,6,178,112,106,187,25,133,153,222,109,
        %OLD%       71,19,88,72,237,7,70,121,111,5,213,75,249>>,
	%OLD% io:write( "TODO: PubKey length should be 256 bit... is not~n" ),
	PrivKey = <<83,231,4,229,27,83,246,52,170,58,250,107,59,159,150,241,14,38,44,
		      9,118,43,123,246,182,148,64,60,61,107,149,120>>,
	PubKey = <<4,199,30,76,103,75,250,222,68,107,137,132,210,98,153,64,196,174,
		     255,70,155,185,234,228,116,63,188,196,165,17,22,216,82,235,155,
		     124,242,150,213,65,202,1,157,219,164,251,140,208,249,83,80,185,
		     179,11,239,158,232,159,252,18,54,159,184,248,221>>,
	PubKeyInfo = #'SubjectPublicKeyInfo' {
		'algorithm' = SigAlg,
		'subjectPublicKey' = PubKey },

	TBSdata = #'KX-TBSDATA' {

		% Ensuring signature freshness / scattering:
		'request-time' = NowStr,

		% Key description information:
		'kvno'         = KVNO,
		'kxname'       = Princ,
		'kxrealm'      = Realm,
		'key-exchange' = PubKeyInfo,

		% Timing information:
		%ERROR% 'till' = (Now rem 10000000) + 86400 * 32,
		'till' = NowStr,

		% Negotiation terms, each in preference order:
		'accept-etype'  = []
		%OPTIONAL% 'accept-group'  = [],
		%OPTIONAL% 'accept-sigalg' = [],
		%OPTIONAL% 'accept-ca'     = []
	},

	Nonce = trunc( rand:uniform() * (1 bsl 32) ),

	%PROBLEM% Cert = crypto:strong_rand_bytes( 600 ),

	% Read the certificate from selfsig-cert.der
	{ok,CertDER} = file:read_file( "selfsig-cert.der" ),
	io:format( "Got ~p bytes worth of Certificate~n",[size( CertDER )] ),
	{ok,Cert} = 'RFC5280':decode( 'Certificate',CertDER ),
	io:format( "Certificate is ~p~n",[Cert] ),

	SigVal = <<0:1,1:1,0:1,1:1,1:1>>,

	Offer = #'KX-OFFER' {

		% Transport-level information:
		'nonce' = Nonce,

		% About the signature:
		'signature-input' = TBSdata,
		'signature-owner' = [ Cert ],
		% 'signature-owner' = [],

		%  The actual signature:
		'signature-alg'   = SigAlg,
		'signature-value' = SigVal
	},

	io:format( "KX-OFFER is~n~p~n",[Offer] ),

	Blob = 'KXOVER':encode( 'KX-OFFER',Offer ),

	io:format( "DERible is~n~p~n",[Blob] ),

	{ok,Binary} = Blob,

	ok = file:write_file( "KX-OFFER.der",Binary ),

	io:format( "Written KX-OFFER.der~n" ).
