package oauthorize.model

import oauthorize.utils._
import oauth2.spec.Req._
import oauth2.spec._
import oauth2.spec.StatusCodes._
import oauth2.spec.model.ErrorResponse

case class AuthzRequest(clientId: String, responseType: ResponseType, redirectUri: String, authScope: Seq[String], approved: Boolean, state: Option[State] = None, user: Option[Oauth2User] = None) extends AuthzRequestValidation
case class AccessTokenRequest(grantType: GrantType, authzCode: String, redirectUri: String, clientId: Option[String]) extends AccessTokenRequestValidation
case class RefreshTokenRequest(grantType: GrantType, refreshToken: String) extends RefreshTokenRequestValidation
case class ClientCredentialsRequest(client: Oauth2Client, scope: Option[String]) extends ClientCredentialsRequestValidation

object ExpirationHelper {
  def isExpired(token: { def validity: Long; def created: Long }): Boolean = { token.created + token.validity * 1000 < System.currentTimeMillis }
}
case class AccessToken(value: String, clientId: String, scope: Seq[String], validity: Long, created: Long, userId: Option[UserId]) {
  def isExpired = ExpirationHelper.isExpired(this)
}
case class RefreshToken(value: String, clientId: String, tokenScope: Seq[String], validity: Long, created: Long, userId: Option[UserId]) {
  def isExpired = ExpirationHelper.isExpired(this)
}

case class AccessAndRefreshTokens(accessToken: AccessToken, refreshToken: Option[RefreshToken] = None)

trait OauthRequest {
  def path: String
  def param(key: String): Option[String]
  def method: String
  def params: Map[String, String]
  override def toString = s"$method '$path' $params"
}

trait OauthResponse
case class OauthRedirect(uri: String, params: Map[String, String]) extends OauthResponse
case class InitiateApproval(authzCode: String, authzRequest: AuthzRequest, client: Oauth2Client) extends OauthResponse
case class Err(error: String, error_description: Option[String] = None, error_uri: Option[String] = None,
  @transient redirect_uri: Option[String] = None, @transient status_code: Int = StatusCodes.BadRequest) extends ErrorResponse(error, error_description, error_uri) with OauthResponse

case class Oauth2Client(clientId: String, clientSecret: String, scope: Seq[String] = Seq(), authorizedGrantTypes: Seq[String] = Seq(),
  redirectUri: String, authorities: Seq[String] = Seq(), accessTokenValidity: Long = 3600, refreshtokenValidity: Long = 604800,
  additionalInfo: Option[String], autoapprove: Boolean = false)

case class UserId(value: String, provider: Option[String])
case class Oauth2User(id: UserId)

case class ClientAuthentication(clientId: String, clientSecret: String)

trait Oauth2Config {
  def authorizeEndpoint: String = "/oauth/authorize"
  def accessTokenEndpoint: String = "/oauth/token"
  def userApprovalEndpoint: String = "/oauth/approve"
}

trait Logging {
  def debug(message: String)
  def warn(message: String)
  def logInfo(message: String)
  def logError(message: String)
  def logError(message: String, t: Throwable)
}

trait Dispatcher {
  def matches(request: OauthRequest): Boolean
}

trait ExecutionContextProvider {
  import scala.concurrent.ExecutionContext
  implicit def oauthExecutionContext: ExecutionContext
}

trait Oauth2Defaults extends Oauth2Config with ExecutionContextProvider with Logging

object ValidationUtils {
  def errForEmpty(value: { def isEmpty: Boolean }, error: Err) = {
    Option(value).filter(!_.isEmpty) match {
      case Some(s: Any) => None
      case _ => Some(error)
    }
  }
}

import ValidationUtils._

trait AuthzRequestValidation {
  this: AuthzRequest =>

  import oauth2.spec.AuthzErrors._

  def getError(implicit client: Oauth2Client): Option[Err] = {
    errClientId orElse
      errResponseType orElse
      errRedirectUri orElse
      errScope
  }

  private def errClientId = {
    errForEmpty(clientId, err(invalid_request, s"mandatory: $client_id"))
  }

  private def errScope(implicit client: Oauth2Client) = {
    errForEmpty(authScope, err(invalid_request, s"mandatory: $scope")) orElse {
      if (authScope.foldLeft(false)((acc, current) => acc || !client.scope.contains(current))) Some(err(invalid_request, s"invalid scope value")) else None
    }
  }

  private def errRedirectUri(implicit client: Oauth2Client) = {
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
      if (grantType != GrantTypes.authorization_code) Some(err(invalid_grant, s"mandatory: $grant_type in ['${GrantTypes.authorization_code}']")) else None
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
}

trait RefreshTokenRequestValidation {
  this: RefreshTokenRequest =>

  import oauth2.spec.AccessTokenErrors._

  def getError: Option[Err] = {
    errGrantType orElse
      errRefreshToken
  }

  private def errGrantType = {
    errForEmpty(grantType, err(invalid_request, s"mandatory: $grant_type")) orElse {
      if (grantType != refresh_token) Some(err(invalid_grant, s"mandatory: $grant_type in ['$refresh_token']")) else None
    }
  }

  private def errRefreshToken = {
    errForEmpty(refreshToken, err(invalid_request, s"mandatory: $refresh_token"))
  }
}

trait ClientCredentialsRequestValidation {
  this: ClientCredentialsRequest =>
  def getError(): Option[Err] = None
}