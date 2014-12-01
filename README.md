oauthorize [![Build Status](https://travis-ci.org/adaptorel/oauthorize.svg?branch=master)](https://travis-ci.org/adaptorel/oauthorize)
==========

An Oauth2 authorization server.

It supports all Oauth2 grant types and aims at adding OpenId Connect on top.

### Teaser

```scala
class Oauth2Filters extends WithFilters(
  OauthorizeCsrfFilter(),
  Oauth2RequestValidator,
  AuthorizationCodeGrant,
  ImplicitGrant,
  ClientCredentialsGrant,
  ResourceOwnerCredentialsGrant,
  AccessTokenEndpoint,
  RefreshTokenEndpoint,
  UserApprovalEndpoint) with Oauth2GlobalErorrHandler
```

### Notes

* The initial version is built on Play but one of the design goals was to completely
decouple as much Oauth2 flow/grants/functionality as possible in the idea of writing
an oauthorize-spray (insert whatever you love here) version at some point.

* All components are customizable/replaceable

* Initial version was built with cake (if you don't know what that is you 
didn't lose anything, just move on), we've switched now on manual constructor based DI.
At least you know what and where. We're still debating if we want to head to something
like Guice for DI. Should be straightforward with the current design, anyways.

### Roadmap

* Documentation (hard coughing here)
* A Spray based impl
