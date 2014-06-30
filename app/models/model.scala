package oauthze.model

import oauthze.utils._
import oauth.spec.Req._
import oauth.spec.ResponseType
import oauth.spec.GrantTypes._
import play.api.libs.json.JsValue

case class AuthzRequest(clientId: String, responseType: ResponseType, state: Option[State], redirectUri: Option[String], scope: Seq[String], approved: Boolean) extends AuthzRequestValidation
case class AccessTokenRequest(grantType: GrantType, authzCode: String, redirectUri: Option[String], clientId: Option[String]) extends AccessTokenRequestValidation

abstract class Token(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long)
case class AccessToken(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long) extends Token(value, client_id, scope, validity, created)
case class RefreshToken(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long) extends Token(value, client_id, scope, validity, created)

case class OauthClient(clientId: String, clientSecret: String, scope: Seq[String] = Seq(), authorizedGrantTypes: Seq[String] = Seq(),
  redirectUri: String, authorities: Seq[String] = Seq(), accessTokenValidity: Long = 3600, refreshtokenValidity: Long = 604800,
  additionalInfo: Option[String], autoapprove: Boolean = false)

case class AccessAndRefreshTokens(accessToken: AccessToken, refreshToken: Option[RefreshToken])

trait AuthzRequestValidation {
  this: AuthzRequest =>

  import oauth.spec.AuthzErrors._

  def getError: Option[JsValue] = {
    errClientId orElse
      errResponseType
  }

  private def errClientId = {
    errForEmpty(clientId, err(invalid_request, s"mandatory: $client_id"))
  }

  private def errResponseType = {

    errForEmpty(responseType, err(invalid_request, s"mandatory: $response_type")) orElse {
      responseType match {
        case ResponseType.code | ResponseType.token => None
        case _ => Some(err(invalid_request, s"mandatory: $response_type in ['${ResponseType.code}','${ResponseType.token}']"))
      }
    }
  }

  private def errForEmpty(value: String, error: JsValue) = {
    Option(value).filter(!_.isEmpty) match {
      case Some(s: String) => None
      case _ => Some(error)
    }
  }
}

trait AccessTokenRequestValidation {
  this: AccessTokenRequest =>

  import oauth.spec.AccessTokenErrors._

  def getError(authzRequest: AuthzRequest, authenticatedClientId: String): Option[JsValue] = {
    errClientId(authzRequest, authenticatedClientId) orElse
      errGrantType orElse
      errCode(authzRequest) orElse
      errForUnmatchingRedirectUri(authzRequest)
  }

  private def errClientId(authzRequest: AuthzRequest, authenticatedClientId: String) = {
    if (authzRequest.clientId != authenticatedClientId) Some(err(invalid_grant, s"mismatched $client_id")) else None
  }

  private def errGrantType = {
    errForEmpty(grantType, err(invalid_request, s"mandatory: $grant_type")) orElse {
      if (grantType != authorization_code) Some(err(invalid_grant, s"mandatory: $grant_type in ['$authorization_code']")) else None
    }
  }

  private def errCode(authzRequest: AuthzRequest) = {
    errForEmpty(authzCode, err(invalid_request, s"mandatory: $code"))
  }

  private def errForUnmatchingRedirectUri(authzRequest: AuthzRequest) = {
    authzRequest.redirectUri map { oauthzRedirectUri =>
      if (!redirectUri.isDefined || oauthzRedirectUri != redirectUri.get) Some(err(invalid_request, s"mismatched: $redirect_uri")) else None
    }
  }.flatten

  private def errForEmpty(value: String, error: JsValue) = {
    Option(value).filterNot(_.trim.isEmpty) match {
      case Some(s: String) => None
      case _ => Some(error)
    }
  }
}