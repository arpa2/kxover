% Signature support, including verification.
%
% This is used to self-sign the KX messages.
%
% For crypto support in Erlang, see
% http://erlang.org/doc/apps/crypto/crypto.pdf
%
% Algorithms ecdsa and sha512 are supported.
%
% From: Rick van Rein <rick@openfortress.nl>

-module( sign ).

-export([
	sign/2,
	verify/3
]).


% Signing is handed off to the crypto module.
% We will probably need to add key management.
% Also anticipated is message parsing and
% algorithm options.
%
sign( Msg,Key ) ->
	crypto:sign( ecdsa,sha512,Msg,Key ).


% Verifying is handed off to the crypto module.
% We will probably need to add key management.
% Also anticipated is message parsing and
% algorithm options.
%
verify( Msg,Sig,Key ) ->
	crypto:verify( ecdsa,sha512,Msg,Sig,Key ).


