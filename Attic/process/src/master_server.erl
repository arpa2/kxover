% Master process for KXOVER.  This module accepts new requests,
% and processes them just far enough to know what Worker should
% act on it.
%
% The Master initiates Worker processes, effectively creating
% many instances of a Petri Net, and interacts to allow the work
% to proceed.  It will order things from a Worker and await the
% response, and then pickup and continue with the designated
% next step.
%
% The Worker is designed to know little or nothing about the
% data exchanged, whereas the Worker has no overview over the
% activity of other Workers, or even the Petri Nets in which
% they partake.  The Master delegates all content-related work
% to the modules of the Worker.
%
% From: Rick van Rein <rick@openfortress.nl>


-module( master_server ).

% % -export([
% % 	init,
% % 	start,
% % 	stop
% % ]).
% 
% 
% %
% % Data used in the Master's loop is a map.
% %
% % A few static names are used for configuration data:
% %   realms => [binary]	% Locally served realms
% %   realms => all	% No limit on served realms
% %
% % Couples of client/server realms map to a Worker:
% %   {CRealm::binary,SRealm::binary} => Worker
% %   Worker => {CRealm::binary,SRealm::binary}
% %             %TODO% Probably need a queue for each Worker too
% %
% 
% 
% %TODO% start()
% 
% 
% %TODO% stop()
% 
% 
% init() ->
% 	loop( #{ realms=>all } ).
% %
% init( RealmList ) ->
% 	loop( #{ realms=>RealmList } ).
% 
% loop( Data ) ->
% 	receive
% 	{ kxmsg,KX } ->
% 		NewData = process_kx ( KX,Data );
% 	{ perpetuum,Worker,TransName } ->
% 		NewData = process_perpetuum( TransName,Worker,Data )
% 	%TODO% Exits...
% 	end,
% 	loop( NewData ).
% 
% 
% % Process a message from Perpetuum, reporting on the progress
% % of a Petri Net.
% %
% process_perpetuum( failed_SRV,Worker,Data ) ->
% 	gen_perpetuum:event( Worker,send_KX_failed,EventData ),
% 	Data;
% process_perpetuum( got_SRV,Worker,Data ) ->
% 	gen_perpetuum:event( Worker,dnssec_req_TLSA,EventData ),
% 	Data;
% process_perpetuum( failed_TLSA,Worker,Data ) ->
% 	gen_perpetuum:event( Worker,send_KX_failed,EventData ),
% 	Data;
% process_perpetuum( signature_error,Worker,Data ) ->
% 	gen_perpetuum:event( Worker,send_KX_failed,EventData ),
% 	Data;
% process_perpetuum( cache_exp_timer,Worker,Data ) ->
% 	case maps:take( Worker,Data ) of
% 	error ->
% 		NewData = Data;
% 	{{_CRealm,_SRealm}=RealmPair,LessData} ->
% 		case maps:take( RealmPair,LessData ) of
% 		error ->
% 			NewData = LessData;
% 		{_Value,NewData} ->
% 			ok
% 		end
% 	end,
% 	NewData;
% process_perpetuum( successfulEnd,Worker,Data ) ->
% 	case maps:take( Worker,Data ) of
% 	error ->
% 		Data;
% 	{{_CRealm,_SRealm}=RealmPair,LessData} ->
% 		case maps:take( RealmPair,LessData ) of
% 		error ->
% 			LessData;
% 		{_Value,NewData} ->
% 			NewData
% 		end
% 	end.
% process_perpetuum( _Others,_Worker,Data ) ->
% 	Data.
% 
% 
% % Process an incoming KX by checking if it is a fresh request
% % or one that can piggyback on existing work.
% %
% process_kx( KX,Data ) ->
% 	NewWorker = kxover_server:start( gen_perpetuum,trans_switch,[] ),
% 	%TODO% Derive CRealm and SRealm from KX
% 	RealmPair = {CRealm,SRealm},
% 	case maps:get( RealmPair,Data,badkey ) of
% 	badkey ->
% 		% No Worker found; create one now
% 		WorkingData = Data#{
% 			RealmPair => NewWorker,
% 			NewWorker => RealmPair };
% 	Worker ->
% 		% Already exists; address this Worker
% 		WorkingData = Data
% 	end,
% 	%TODO% May be ignored; we should then queue and respond later
% 	gen_perpetuum:event( NewWorker,dnssec_req_SRV,KX ),
% 	WorkingData.
% 
% 
