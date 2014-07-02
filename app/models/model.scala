package oauthze.model

import oauthze.utils._
import oauth2.spec.Req._
import oauth2.spec.ResponseType
import oauth2.spec.GrantTypes._
import oauth2.spec.StatusCodes._
import oauth2.spec.Err
import scala.collection.SeqLike
import oauth2.spec.StatusCodes

case class AuthzRequest(clientId: String, responseType: ResponseType, redirectUri: String, authScope: Seq[String], approved: Boolean, state: Option[State] = None) extends AuthzRequestValidation
case class AccessTokenRequest(grantType: GrantType, authzCode: String, redirectUri: String, clientId: Option[String]) extends AccessTokenRequestValidation

abstract class Token(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long)
case class AccessToken(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long) extends Token(value, client_id, scope, validity, created)
case class RefreshToken(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long) extends Token(value, client_id, scope, validity, created)

case class OauthClient(clientId: String, clientSecret: String, scope: Seq[String] = Seq(), authorizedGrantTypes: Seq[String] = Seq(),
  redirectUri: String, authorities: Seq[String] = Seq(), accessTokenValidity: Long = 3600, refreshtokenValidity: Long = 604800,
  additionalInfo: Option[String], autoapprove: Boolean = false)

case class AccessAndRefreshTokens(accessToken: AccessToken, refreshToken: Option[RefreshToken])

trait AuthzRequestValidation {
  this: AuthzRequest =>

  import oauth2.spec.AuthzErrors._

  def getError(implicit client: OauthClient): Option[Err] = {
    errClientId orElse
      errResponseType orElse
      errRedirectUri orElse
      errScope
  }

  private def errClientId = {
    errForEmpty(clientId, err(invalid_request, s"mandatory: $client_id"))
  }

  private def errScope(implicit client: OauthClient) = {
    errForEmpty(authScope, err(invalid_request, s"mandatory: $scope")) orElse {
      if (authScope.foldLeft(false)((acc, current) => acc || !client.scope.contains(current))) Some(err(invalid_request, s"invalid scope value")) else None
    }
  }

  private def errRedirectUri(implicit client: OauthClient) = {
    errForEmpty(redirectUri, err(invalid_request, s"mandatory: $redirect_uri")) orElse
      (if (redirectUri != client.redirectUri) Some(err(invalid_request, s"missmatched: $redirect_uri")) else None)
  }

  private def errResponseType = {
    errForEmpty(responseType, err(invalid_request, s"mandatory: $response_type")) orElse {
      responseType match {
        case ResponseType.code | ResponseType.token => None
        case _ => Some(err(invalid_request, s"mandatory: $response_type in ['${ResponseType.code}','${ResponseType.token}']"))
      }
    }
  }

  private def errForEmpty(value: { def isEmpty: Boolean }, error: Err) = {
    Option(value).filter(!_.isEmpty) match {
      case Some(s: Any) => None
      case _ => Some(error)
    }
  }
}

trait AccessTokenRequestValidation {
  this: AccessTokenRequest =>

  import oauth2.spec.AccessTokenErrors._

  def getError(authzRequest: AuthzRequest, authenticatedClientId: String): Option[Err] = {
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
    errForEmpty(redirectUri, err(invalid_request, s"mandatory: $redirect_uri")) orElse {
      if (authzRequest.redirectUri != redirectUri) Some(err(invalid_request, s"mismatched: $redirect_uri")) else None
    }
  }

  private def errForEmpty(value: String, error: Err) = {
    Option(value).filterNot(_.trim.isEmpty) match {
      case Some(s: String) => None
      case _ => Some(error)
    }
  }
}