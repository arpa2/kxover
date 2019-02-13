Policy Example for Key Version Numbering
========================================

>   *Crossover keys are distinguishable by the combination of their principal
>   name and realm, their encryption type (e-type) and the key version number
>   (kvno). These kvno values must somehow be established between the client and
>   service realm.*

It is possible to use one kvno value for a variety of e-types, so the KX-OFFER
exchanges one kvno only. The client may send one as a suggestion of a free
value, and the server finally decides. The client generally should follow the
server, but has the freedom to drop an offered key and try again in case of
conflict.

The reason for having some negotiation but let the KX-OVER server decide is that
its service KDC is supposed to have keys available at least as long as the
client, simply for reasons of being able to support clients using them after
they once got hold of it.

Limited Use of Integer Range
----------------------------

There are a few rules that can guide the selection of the kvno. In general, it
would be a rotary scheme, but it is better not go through the entire integer
range, for a number of reasons.

First, any manually established keys would be numbered lowly, usually starting
at 0 or 1. There may also be hard-coded choices for values such as 0 or -1 or
\~0. It is generally good to avoid these when automatically generating a kvno
for KXOVER, so as not to interfere with any such practices. There is no reason
why fixed secrets could not be setup alongside impromptu realm crossover!

Second, some implementations get confused about negative numbers in a 16-bit
value range, let along any further bits that might be added. Formally, the
definition is an unsigned integer value that would fit in 32 bits, but leave it
to implementations to get this wrong, especially in DER encoding which always
sends signed integers (but might prefix a zero byte to avoid reading a sign in a
high bit).

We don't need that much either. Let's take a look at how small our requirements
actually are.

-   We are not likely to let keys be valid for as long as a year, so a rotary
    scheme based on a measure of progress in a calendar year would work. This
    means that we should cover up to 366 days only. Wrap-around of the range
    would fall in the period of Christmas and New Year.

-   We are not likely to allow more than 10 re-requests for crossover between
    the same realms on one day. That would mean that kvno values take up 366 \*
    10 values.

-   We can use a range of values in the top of a 15-bit range, perhaps starting
    at 20,000.

-   To get even humanly readable kvno values, we might choose a scheme  of
    digits MMDDS with month MM, day DD and a daily sequence counter for the
    crossover request ranging from 0 up to 9.  We could add this to 20,000 and
    find values like 27,040 for the first attempt on July 4th, and 27,041 for
    the second attempt on that same day.

-   Month 12 might be mentioned as MM=12 and/or MM=00, as that might help a
    client KDC with a rotary scheme of kvno values.  (This is not actually
    tested, but a theoretic option that might be useful in practice.)

Several variations are possible, but in general it is a good idea to revolve in
a relatively small rotary range of kvno values.

A Telling Experiment
--------------------

We need to learn if a rotary scheme for kvno values is a problem. At least MIT
krb5 selects a default kvno based on a timestamp, rather than merely the
sequence order.

Software that is less clever might exist, but would then have standard hickups
around the change of year, which would simplify handling; it may be covered in
holidays, a cron job could erase keys from last year, or the user may learn to
wipe caches, retry an attempt and so on. In general however, there should be no
problems as a result of the rotary scheme.

We might for example consider to setup kvnos for month 12 and 0 at the same
time, perhaps even with the same keys, and prefer handing out the kvno from
month 0 in the client KDC while the server KDC accepts both. We shall not do
this until it becomes a necessity, because it makes the software more complex
than the plain rotary scheme.

What our Software Uses
----------------------

We don't let the client suggest a key; the server knows best. The server will
assume a range starting at 20,000 and add to that MMDDS, where MM is the month,
DD is the day and S is the sequence number within the day, counting from 0. So
key 32051 would be for month 12, day 5, daily second attempt numbered 1.

The kvno format makes it simple to see expired keys, both automatically and by a
reviewing human; this helps with the timely removal of those keys, as is
necessary to prepare the cycle for another round.

Needless to say that we want to allow trimming down on the number of daily
crossover attempts to a count lower than 10.  But in reality we may want to
impose a limit over a longer time, so this may not be the right place to do it.
Generally, there are more things that we might want to configure, and we will
learn about the wishes in practice before we develop this.

 
