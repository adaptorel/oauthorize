package oauthorize.playapp

import grants._
import oauthorize.service._
import play.api.mvc.WithFilters
import csrf.OauthorizeCsrfFilter

trait OauthMix extends Oauth2DefaultsPlay
  with InMemoryOauth2Store
  with DefaultTokenGenerator
  with BCryptClientSecretHasher
  with BCryptUserPasswordHasher

object Oauth extends OauthMix

object Oauth2RequestValidator extends Oauth2RequestValidatorPlay with OauthMix
object AuthorizationCodeGrant extends AuthorizationCodePlay with OauthMix
object ImplicitGrant extends ImplicitGrantPlay with OauthMix
object ClientCredentialsGrant extends ClientCredentialsGrantPlay with OauthMix
object AccessTokenEndpoint extends AccessTokenEndpointPlay with OauthMix
object RefreshTokenEndpoint extends RefreshTokenEndpointPlay with OauthMix
object ResourceOwnerCredentialsGrant extends ResourceOwnerCredentialsGrantPlay with OauthMix with SecureSocialUserStore
object UserApprovalEndpoint extends UserApprovalPlay with OauthMix

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
