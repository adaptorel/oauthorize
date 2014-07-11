package app

import oauthze.model._
import oauthze.service._
import grants._
import grants.playimpl._
import play.api.mvc._

trait OauthMix extends OauthConfig
  with InMemoryOauthClientStore
  with DefaultAuthzCodeGenerator
  with BCryptPasswordEncoder

object Oauth extends OauthMix

object OauthRequestValidator extends OauthRequestValidatorPlay with OauthMix
object CodeGrant extends AuthorizationCodePlay with OauthMix
object ImplicitGrant extends ImplicitGrantPlay with OauthMix
object ClientCredentialsGrant extends ClientCredentialsGrantPlay with OauthMix
object AccessToken extends AccessTokenEndpointPlay with OauthMix
object UserApproval extends UserApprovalPlay with OauthMix

class AppFilters extends WithFilters(OauthRequestValidator, CodeGrant, ImplicitGrant, ClientCredentialsGrant, AccessToken, UserApproval)