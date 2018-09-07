#!/usr/bin/env escript
%
% drive_master_network.erl -- Run through the Petri Nets for the KXOVER client and server
%
% From: Rick van Rein <rick@openfortress.nl>


-include_lib( "kxover/include/RFC4120.hrl" ).
-include_lib( "kxover/include/RFC5280.hrl" ).
-include_lib( "kxover/include/KXOVER.hrl" ).


main( [] ) ->
	main( ["KX-OFFER.der","KX-RESPONSE.der"] )
;
main( [_FileKXoffer,_FileKXresponse|_Args] ) ->

	% Start the Unbound service process
	%
	unbound:start(),
	io:format( "Started Unbound service~n" ),

	% Start a kxover_client with logic_client backend
	%
	{ok,Client} = kxover_client:start_link( gen_perpetuum,trans_switch,logic_client:all_hooks() ),
	io:format( "Running client in process ~p~n",[Client] ),
	CliRef = monitor( process,Client ),

	% Start a kxover_server with logic_server backend
	%
	%TODO% {ok,Server} = kxover_server:start_link( gen_perpetuum,trans_switch,logic_server:all_hooks() ),
	{ok,Server} = kxover_server:start( gen_perpetuum,trans_switch,logic_server:all_hooks() ),
	io:format( "Running server in process ~p~n",[Server] ),
	Ref = monitor( process,Server ),

	%%TODO%% Ugly, ugly calendar time... :'-(
	%
	Now = erlang:system_time( microsecond ),
	_NowSec  = Now div 1000000,
	_NowUSec = Now rem 1000000,
	{{NowYear, NowMonth, NowDay}, {NowHour, NowMinute, NowSecond}} = calendar:now_to_datetime( erlang:now() ),
	NowStr = lists:flatten(io_lib:format("~4..0w-~2..0w-~2..0wT~2..0w:~2..0w:~2..0w",[NowYear,NowMonth,NowDay,NowHour,NowMinute,NowSecond])),

	% Construct the initial request to drive the client
	%
	InitialRequest = #'KDC-REQ' {
		pvno = 5,
		'msg-type' = 12,
		'req-body' = #'KDC-REQ-BODY' {
			realm = <<"SURFNET.NL">>,
			sname = #'PrincipalName' {
				'name-type' = 2,
				'name-string' = [ <<"krbtgt">>, <<"ARPA2.NET">> ]
			},
			nonce = trunc( rand:uniform() * (1 bsl 32) ),
			till = NowStr,  %%%TODO:TOO:SHORT%%%
			etype = [ 18, 20, 26 ]
				% aes256-cts-hmac-sha1-96
				% aes256-cts-hmac-sha384-192
				% camellia256-cts-cmac
		}
	},

	% Send the initial request to the client
	%
	noreply = gen_perpetuum:event( Client,krbtgtMissing,{InitialRequest,have_krbtgt,have_dawn_krbtgt,need_SRV} ),

	% Pickup the response event, possibly reporting an available krbtgt
	%
	%TODO% Actually make use of GotOne / WalkThrough flags
	%
	receive
	{ perpetuum,Client,have_krbtgt,noreply } ->
		io:format( "Already have a fresh krbtgt (TODO:UNPLOTTED)~n" ),
		_GotOne = true,
		_WalkThrough = false;
	{ perpetuum,Client,have_dawn_krbtgt,noreply } ->
		io:format( "Already have a dawning krbtgt; refreshments are necessary (TODO:UNPLOTTED)~n" ),
		_GotOne = true,
		_WalkThrough = true;
	{ perpetuum,Client,need_SRV,noreply } ->
		io:format( "No krbtgt available yet; getting one~n" ),
		_GotOne = false,
		_WalkThrough = true;
	Error1c ->
		io:format( "Unexpected return value Error1c~n~p~n",[Error1c] ),
		error( Error1c )
	after 5000 ->
		demonitor( CliRef,[flush] ),
		error( timeout )
	end,
	%DEBUG% io:format( "Marking = ~p~n",[gen_perpetuum:marking( Client )] ),

	% Request an SRV record for the remote realm KDC under DNSSEC protection
	%
	noreply = gen_perpetuum:event( Client,dnssec_req_SRV,{ got_SRV,failed_SRV,<< "_kerberos._udp.stanford.edu" >> }),

	% Await the response to the SRV query
	%
	receive
	{ perpetuum,Client,got_SRV,noreply } ->
		io:format( "Succeeded retrieving SRV record~n" );
	{ perpetuum,Client,failed_SRV,noreply } ->
		io:format( "Failure retrieving SRV record~n" ),
		error( failed_SRV );	% Unsupported track
	Error2c ->
		io:format( "Unexpected return value Error2c~n~p~n",[Error2c] ),
		error( Error2c )
	after 5000 ->
		demonitor( CliRef,[flush] ),
		error( timeout )
	end,

	% Based on the SRV data, now request TLSA and A/AAAA as well
	%
	noreply = gen_perpetuum:event( Client,dnssec_req_TLSA,{ got_TLSA,failed_TLSA,<< "_443._tcp.internet.nl" >> }),
	noreply = gen_perpetuum:event( Client,dns_req_A_AAAA,{ got_A_AAAA,failed_A_AAAA,<< "internetwide.org" >> }),

	% The A_AAAA is trivial in Erlang, so lap it up and continue immediately
	%
	KXofferSend = receive
	{ perpetuum,Client,got_A_AAAA,noreply } ->
		{ reply,KXofferToSend} = gen_perpetuum:event( Client,send_KX_req,{} ),
		io:format( "Constructed KX-OFFER from client: ~p~n",[KXofferToSend] ),
		KXofferToSend;
	Error3c ->
		io:format( "Unexpected return value Error3c~n~p~n",[Error3c] ),
		error( Error3c )
	after 5000 ->
		demonitor( CliRef,[flush] ),
		{ error,timeout }
	end,

	% Receive the TLSA completion or failure
	% Note: This would normally run in parallel with the server;
	%       We, however, share a reply channel and must be less loose.
	%
	receive
	{ perpetuum,Client,got_TLSA,noreply } ->
		io:format( "Successful TLSA inquiry~n" );
	{ perpetuum,Client,failed_TLSA,noreply } ->
		gen_perpetuum:event( Client,'KXwoDANE',{} ),
		io:format( "Failed on TLSA query~n" );
	{ 'DOWN',CliRef,process,_Name1,normal } ->
		%DEBUG% io:format( "Stopped ~p~n",[Name1] );
		ok;
	{ 'DOWN',CliRef,process,_Name1,_Reason1 }=Failure1 ->
		%DEBUG% io:format( "CRASH: ~p~n",[Failure1] )
		{ error,{ crashed,Failure1 }};
	Error4c ->
		io:format( "Unexpected return value Error4c~n~p~n",[Error4c] ),
		error( Error4c )
	after 5000 ->
		demonitor( CliRef,[flush] ),
		{ error,timeout }
	end,

	% Send the KX-OFFER to the server
	%
	%TODO% KX-OFFER --> KX-REQ
	{ok,KXofferCli} = 'KXOVER':encode( 'KX-OFFER',KXofferSend ),
	noreply = gen_perpetuum:event( Server,recv_KX_req,KXofferCli ),

	% Request an SRV record under DNSSEC
	%
	noreply = gen_perpetuum:event( Server,dnssec_req_SRV,{ got_SRV,failed_SRV,<< "_kerberos._udp.stanford.edu" >> }),

	% Await the response to the SRV query
	%
	receive
	{ perpetuum,Server,got_SRV,noreply } ->
		io:format( "Succeeded retrieving SRV record~n" );
	{ perpetuum,Server,failed_SRV,noreply } ->
		io:format( "Failure retrieving SRV record~n" );
	Error1s ->
		io:format( "Unexpected return value Error1s~n~p~n",[Error1s] ),
		error( Error1s )
	after 5000 ->
		error( timeout )
	end,

	% Request a TLSA record under DNSSEC
	%
	noreply = gen_perpetuum:event( Server,dnssec_req_TLSA,{ got_TLSA,failed_TLSA,<< "_443._tcp.internet.nl" >> }),

	% Await the response to the TLSA query
	%
	receive
	{ perpetuum,Server,got_TLSA,noreply } ->
		io:format( "Succeeded retrieving TLSA record~n" );
	{ perpetuum,Server,failed_TLSA,noreply } ->
		io:format( "Failure retrieving TLSA record~n" );
	Error2s ->
		io:format( "Unexpected return value Error2s~n~p~n",[Error2s] ),
		error( Error2s )
	after 5000 ->
		error( timeout )
	end,

	% Request KX signature verification based on TLSA
	%
	%TODO% noreply = gen_perpetuum:event( Server,signature_verify,{ signature_good,signature_error }),
	noreply = gen_perpetuum:event( Server,signature_verify,{ signature_good,signature_good }),  %%%LIES:_NOT_ALWAYS_GOOD%%%
	io:format( "Returned from signature verification request~n" ),

	% Await the response to the signature verification
	%
	receive
	{ perpetuum,Server,signature_good,noreply } ->
		io:format( "Signature on KX verifies under TLSA ###LIES:_NOT_ALWAYS_GOOD###~n" );
	{ perpetuum,Server,signature_error,noreply } ->
		io:format( "Signature on KX failed to verify under TLSA~n" );
	Error3s ->
		io:format( "Unexpected return value Error3s~n~p~n",[Error3s] ),
		error( Error3s )
	after 5000 ->
		error( timeout )
	end,

	% Perform the ECDHE computation and derive the crossover key
	%
	noreply = gen_perpetuum:event( Server,ecdhe2krbtgt,{} ),

	% Perform the storage of the crossover key
	%
	noreply = gen_perpetuum:event( Server,store_krbtgt_kdb,{} ),

	% Send the KX response to the requester
	%
	{ reply,KXofferRecv } = gen_perpetuum:event( Server,send_KX_resp,{} ),
	io:format( "KXofferRecv = ~p~n",[KXofferRecv] ),

	% Hint that excess keys may be removed
	%
	io:format( "Signaling to remove shortest~n" ),
	gen_perpetuum:signal( Server,remove_shortest,{} ),
	io:format( "Signaled  to remove shortest~n" ),
	receive
	{ perpetuum,Server,remove_shortest,{retry,marking} } ->
		io:format( "Removal of shortest is not a concern at this point~n" );
	{ perpetuum,Server,remove_shortest,noreply } ->
		io:format( "Removal of shortest has been taken into consideration~n" );
	Error4s ->
		io:format( "Unexpected return value Error4s~n~p~n",[Error4s] ),
		error( Error4s )
	after 5000 ->
		error( timeout )
	end,

	% Perform cleanup of a successful crossover key exchange
	%
	noreply = gen_perpetuum:event( Server,successfulEnd,{} ),

	%TODO% Remove excess keys, if any

	% Report about the KX-OFFER sent by the server
	%
	{ok,KXofferSrv} = 'KXOVER':encode( 'KX-OFFER',KXofferRecv ),
	io:format( "KXofferSrv = ~p~n",[KXofferSrv] ),

	% Continue processing the server-sent KX-OFFER in the client
	%
	gen_perpetuum:event( Client,got_KX_resp,KXofferSrv ),

	% Request KX signature verification based on TLSA
	%
	%TODO% noreply = gen_perpetuum:event( Client,signature_verify,{ signature_good,signature_error }),
	noreply = gen_perpetuum:event( Client,signature_verify,{ signature_good,signature_good }),  %%%LIES:_NOT_ALWAYS_GOOD%%%
	io:format( "Returned from signature verification request~n" ),

	% Await the response to the signature verification
	%
	receive
	{ perpetuum,Client,signature_good,noreply } ->
		io:format( "Signature on KX verifies under TLSA ###LIES:_NOT_ALWAYS_GOOD###~n" );
	{ perpetuum,Client,signature_error,noreply } ->
		io:format( "Signature on KX failed to verify under TLSA~n" );
	Error5c ->
		io:format( "Unexpected return value Error5c~n~p~n",[Error5c] ),
		error( Error5c )
	after 5000 ->
		error( timeout )
	end,

	% Perform the ECDHE computation and derive the crossover key
	%
	noreply = gen_perpetuum:event( Client,ecdhe2krbtgt,{} ),

	% Perform the storage of the crossover key
	%
	noreply = gen_perpetuum:event( Client,store_krbtgt_kdb,{} ),

	% Send the constructed krbtgt to all requesting clients
	%
	noreply = gen_perpetuum:event( Client,send_krbtgt_to_all_requesters,{} ),

	% Successfully end the krbtgt construction client process
	%
	noreply = gen_perpetuum:event( Client,successfulEnd,{} ),

	% Report the final marking for the KXOVER Client
	%
	io:format( "Final marking for KXOVER client is~n~p~n",[ gen_perpetuum:marking( Client ) ] ),

	% Stop the client and harvest its response
	%
	%TODO% kxover_client:stop( Client,bored_to_death ),
	kxover_client:stop( Client ),
	FinalC = receive
	{ 'DOWN',CliRef,process,_Name2,normal } ->
		%DEBUG% io:format( "Stopped ~p~n",[Name2] );
		ok;
	{ 'DOWN',CliRef,process,_Name2,_Reason2 }=Failure2 ->
		%DEBUG% io:format( "CRASH: ~p~n",[Failure2] )
		{ error,{ crashed,Failure2 }}
	after 5000 ->
		demonitor( CliRef,[flush] ),
		{ error,timeout }
	end,

	% Report the final marking for the KXOVER Server
	%
	io:format( "Final marking for KXOVER server is~n~p~n",[ gen_perpetuum:marking( Server ) ] ),

	% Stop the server and harvest its response
	%
	%TODO% kxover_server:stop( Server,bored_to_death ),
	kxover_server:stop( Server ),
	FinalS = receive
	{ 'DOWN',Ref,process,_Name1s,normal } ->
		%DEBUG% io:format( "Stopped ~p~n",[Name1s] );
		ok;
	{ 'DOWN',Ref,process,_Name1s,_Reason1s }=Failure1s ->
		%DEBUG% io:format( "CRASH: ~p~n",[Failure1s] )
		{ error,{ crashed,Failure1s }}
	after 5000 ->
		demonitor( Ref,[flush] ),
		{ error,timeout }
	end,

	% Stop the Unbound service process
	%
	unbound:stop (),

	% Report our code's last sign of life
	%
	io:format( "At the end, client got~n~p~nAt the end, server got~n~p~n",[FinalC,FinalS] ).




