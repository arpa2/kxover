# README to the Petri-nets for KXOVER

> *This directory contains the process definitions for KXOVER in terms of
> Petri nets.*

The files in this directory describe the automated workflow process for
KXOVER.  These are automatically mapped to executing code, and linked with
library routines for the transitions.


## Working with Petri Nets

There are
[several tools](https://github.com/vanrein/perpetuum/blob/master/TOOLS.MD)
for working with Petri nets.  Some of these are prepared for working on
these files, others may be possible too; let us know if you find new uses!

You can use the
[GreatSPN Editor](http://www.di.unito.it/%7Eamparore/mc4cslta/editor.html)
to edit the `.PNPRO` files, and to simulate runs.  Especially the simulations
are quite useful.  If you need to, you can make changes and should then save
those in the `.PNPRO` format, which we consider the source format.

The editor will let you export `.PNML` files, which is a standard format
that suffices to capture the simple Petri nets that we are using:

  * Simple P/T Petri Nets, no colour
  * Multiplicity on arcs through inscription texts
  * Inhibitor arcs are supported through arc types

More tools will be able to produce `.PNML` files, as this is a standard,
but we found compatibility to be less than perfect, in spite of this being
a standard.  The problem is that `.PNML` files are really simple Petri nets,
and most software aims for higher goals because it stems from Petri net
research.  IOW, YMMV.  This is why we settled for the `.PNPRO` format as
our source format.  But by all means, try other tools and let us know if you
encounter good alternatives!

The `.pdf` format was printed from GreatSPN (which also has nice code for
drawing pretty diagrams) and we used Gimp to produce the `.png` from that.


## Deriving Code from Petri Nets

Derivation of executing code is done using the
[Perpetuum](https://github.com/vanrein/perpetuum)
software package.  It is linked with code for firing events,
Petri-net scheduling and a runtime, all very small and generic bits of code.
This is done with the `perpetuum-codegen` executable.

The thusly generated code implements the ideas described under
[Using Perpetuum](https://github.com/vanrein/perpetuum/blob/master/USING.MD),
specificall for
[actions](https://github.com/vanrein/perpetuum/blob/master/USING.MD#implement-your-actions)
and
[events](https://github.com/vanrein/perpetuum/blob/master/USING.MD#implement-your-events).

There is a lot of output from `perpetuum-codegen`; it is
[described here](https://github.com/vanrein/perpetuum/blob/master/QUICKSTART.MD).

