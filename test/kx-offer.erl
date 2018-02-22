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
	Now = erlang:system_time( microsecond ),
	NowSec  = Now div 1000000,
	NowUSec = Now rem 1000000,
	{{NowYear, NowMonth, NowDay}, {NowHour, NowMinute, NowSecond}} = calendar:now_to_datetime( erlang:now() ),
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

	KVNO = 123,

	%TODO% Get a real Signature Algorithm OID in here (but who defines them?)
	SigAlg_OLD = #'AlgorithmIdentifier' {
		algorithm = { 1,2,840,113549,1,1,1 },
		parameters = <<5,0>> },
	SigAlg = #'AlgorithmIdentifier' {
		algorithm = {1,2,840,10045,2,1},
		parameters = <<6,5,43,129,4,0,10>> },
	PubKey_OLD = <<0:1,1:1,0:1,1:1,1:1>>,
	PubKey = <<4,205,3,102,67,82,53,171,60,251,102,71,179,236,170,16,4,211,75,
              113,103,248,249,244,204,247,6,178,112,106,187,25,133,153,222,109,
              71,19,88,72,237,7,70,121,111,5,213,75,249>>,
	PubKeyInfo = #'SubjectPublicKeyInfo' {
		'algorithm' = SigAlg,
		'subjectPublicKey' = PubKey },

	TBSdata = #'KX-TBSDATA' {

		% Ensuring signature freshness / scattering:
		'authenticator' = Author,

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
