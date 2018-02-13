#!/usr/bin/env escript
%
% drive_master_server.erl -- Run through the Petri Net for the KXOVER server
%
% From: Rick van Rein <rick@openfortress.nl>


main( [] ) ->
	main( ["KX-OFFER.der"] )
;
main( [FileKXoffer|_Args] ) ->

	% Read the KX-OFFER to use from a file
	%
	{ok,KXoffer} = file:read_file( FileKXoffer ),
	io:format( "Got ~p bytes worth of KX-OFFER from ~p~n",[size( KXoffer ),FileKXoffer] ),

	% Start the Unbound service process
	%
	%TODO% unbound:start( [ { forwarders,<<"10.0.2.5">> } ] ),
	unbound:start(),

	% Start a kxover_server with logic_server backend
	%
	%TODO% {ok,Server} = kxover_server:start_link( gen_perpetuum,trans_switch,logic_server:all_hooks() ),
	{ok,Server} = kxover_server:start( gen_perpetuum,trans_switch,logic_server:all_hooks() ),
	io:format( "Running server in process ~p~n",[Server] ),
	Ref = monitor( process,Server ),

	% Send the KX-OFFER to the server
	%
	%TODO% KX-OFFER --> KX-REQ
	noreply = gen_perpetuum:event( Server,recv_KX_req,KXoffer ),

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
	Error1 ->
		io:format( "Unexpected return value ~p~n",[Error1] ),
		error( Error1 )
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
	Error2 ->
		io:format( "Unexpected return value ~p~n",[Error2] ),
		error( Error2 )
	after 5000 ->
		error( timeout )
	end,

	% Request KX signature verification based on TLSA
	%
	noreply = gen_perpetuum:event( Server,signature_verify,{ signature_good,signature_error }),
	io:format( "Returned from signature verification request~n" ),

	% Await the response to the signature verification
	%
	receive
	{ perpetuum,Server,signature_good,noreply } ->
		io:format( "Signture on KX verifies under TLSA~n" );
	{ perpetuum,Server,signature_error,noreply } ->
		io:format( "Signature on KX failed to verify under TLSA~n" );
	Error3 ->
		io:format( "Unexpected return value ~p~n",[Error3] ),
		error( Error3 )
	after 5000 ->
		error( timeout )
	end,

	%DEBUG% io:format( "Something returned is ~p~n",[STH] ),

	% Cause an error to see what it does
	%
	%TODO% noreply = gen_perpetuum:event( Server,undefined,'EventDataString' ),

	% Stop the server and harvest its response
	%
	%TODO% kxover_server:stop( Server,bored_to_death ),
	kxover_server:stop( Server ),
	Final = receive
	{ 'DOWN',Ref,process,_Name1,normal } ->
		%DEBUG% io:format( "Stopped ~p~n",[Name1] );
		ok;
	{ 'DOWN',Ref,process,_Name1,_Reason1 }=Failure1 ->
		%DEBUG% io:format( "CRASH: ~p~n",[Failure1] )
		{ error,{ crashed,Failure1 }}
	after 5000 ->
		demonitor( Ref,[flush] ),
		{ error,timeout }
	end,

	% Stop the Unbound service process
	%
	unbound:stop (),

	% Report our code's last sign of life
	%
	io:format( "At the end, got ~p~n",[Final] ).

