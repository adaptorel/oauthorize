package controllers

import oauthze.service._
import play.api.libs.json.Json

object json {
  import oauth2.spec.model._
  implicit val AuthzCodeResponseFormat = Json.format[AuthzCodeResponse]
  implicit val ImplicitResponseFormat = Json.format[ImplicitResponse]
  implicit val AccessTokenResponseFormat = Json.format[AccessTokenResponse]
}

trait Oauth extends InMemoryOauthClientStore with DefaultAuthzCodeGenerator with BCryptPasswordEncoder

object Application extends Authorize with UserApproval with AccessToken with Oauth