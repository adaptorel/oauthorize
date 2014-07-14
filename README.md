oauthorize
==========

An Oauth2 provider. Lightweight but tries to closely follow the spec.

It supports all Oauth2 grant types and aims at adding OpenId Connect on top.

### Notes

The initial version is built on Play but one of the design goals was to completely
decouple as much Oauth2 flow/grants/functionality as possible in the idea of writing
an oauthorize-spay (or whatever) version at some point.

The relevant Oauth2 code you're looking for if not interested in the (default) Play
version is in the 'zlibs' sbt subproject.
