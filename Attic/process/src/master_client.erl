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

-module( master_client ).


