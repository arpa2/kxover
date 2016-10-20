This code patched MIT krb5 1.13.3 to bypass questions to kxoverd.

During Oriol Caño's MSc thesis work, we modified AS-REQ and TGS-REQ
handling.  This was in the hope that we could use these messages from
[RFC4120](https://tools.ietf.org/html/rfc4120)
between the client KDC and service KDC without modification.  While
constructing the proof of concept, we learnt that this is not possible
without "hacking" the intent of the messages; some required fields make
no sense in our use of the messages.

The new approach therefore consists of detection of new [APPLICATION n]
tags, with their own message format.  This has the added benefit of
routing messages at a lower layer in the KDC, where it seems to make
more sense, as well as reducing complexity in the already heavy handling
for the existing messages.

As a result, our initial patches will not be part of the eventual code.
