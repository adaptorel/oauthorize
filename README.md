oauthorize [![Build Status](https://travis-ci.org/adaptorel/oauthorize.svg?branch=master)](https://travis-ci.org/adaptorel/oauthorize)
==========

An Oauth2 authorization server. It supports all Oauth2 grant types.

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
* OpenId Connect

### Why

Why on earh would you write an Oauth2 authorization server?
'Cause after 10+ years of Java and Spring framework development, Spring Oauth2 
decided to switch to Java Config and all this new shiny stuff and suddenly 
we have found ourselves not being able to understand, debug and ultimately 
customize/tweak Spring Security Oauth2 to our usecase. The XML based version was 
running like a charm but all the Spring ecosystem heads away from it so all 
docs and samples we could use were outdated/not supported anymore.

Also there are two other notable Oauth2 authorization server impls out there, one  
also based on Spring Framework and another one just not as open as we'd like aka
only the code is available, if you whish to do anything else with it you have to head
towards the paid version. (Insert links here, I will, it's just months since I evaluated
them, I need to look into them again).

Thus, oauthorize was born, after 2 weekends of coding a prototype for the 
client_credentials Oauth2 flow :-) 
