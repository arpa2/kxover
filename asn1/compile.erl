#!/usr/bin/env escript
%
% Compile the various .asn1 scripts to a compiler
%
% Note that we're not doing this in an automatic build;
% we use Erlang.mk instead (which demonstrated that ASN.1
% files can be fed directly into erlc... blush...)
%
% From: Rick van Rein <rick@openfortress.nl>


main ([]) ->
	io:format( "Successfully compiled all ASN.1 input files to Erlang~n" ),
	0
;
main ([File|MoreFiles]) ->
	io:format( "Compiling ~p to Erlang~n",[File] ),
	Compiled = asn1ct:compile (File, [der,maps]),
	case Compiled of
	ok ->
		% Perhaps: asn1ct:test( ... )
		main( MoreFiles );
	Error ->
		io:format ("Errors in ~p~n:~n~p~n",[File,Error] ),
		1
	end.

