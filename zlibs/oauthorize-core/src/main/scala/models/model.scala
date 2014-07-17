package oauthorize.model

import oauth2.spec.StatusCodes
import oauth2.spec.model.ErrorResponse

import types._
case class AuthzRequest(clientId: String, responseType: ResponseType, redirectUri: String, authScope: Seq[String], approved: Boolean, state: Option[State] = None, user: Option[Oauth2User] = None) extends AuthzRequestValidation
case class AccessTokenRequest(grantType: GrantType, authzCode: String, redirectUri: String, clientId: Option[String]) extends AccessTokenRequestValidation
case class RefreshTokenRequest(grantType: GrantType, refreshToken: String) extends RefreshTokenRequestValidation
case class ClientCredentialsRequest(client: Oauth2Client, scope: Option[String]) extends ClientCredentialsRequestValidation
case class ResourceOwnerCredentialsRequest(grantType: GrantType, username: String, password: String, authScope: Seq[String]) extends ResourceOwnerCredentialsRequestValidation

abstract class Token {
  def value: String
  def clientId: String
  def tokenScope: Seq[String]
  def validity: Long
  def created: Long
  def userId: Option[UserId]
  def isExpired = created + validity * 1000 < System.currentTimeMillis
}

case class AccessToken(value: String, clientId: String, tokenScope: Seq[String], validity: Long, created: Long, userId: Option[UserId]) extends Token
case class RefreshToken(value: String, clientId: String, tokenScope: Seq[String], validity: Long, created: Long, userId: Option[UserId]) extends Token

case class AccessAndRefreshTokens(accessToken: AccessToken, refreshToken: Option[RefreshToken] = None)

trait OauthRequest {
  def path: String
  def param(key: String): Option[String]
  def header(key: String): Option[String]
  def method: String
  def params: Map[String, String]
  override def toString = s"$method '$path' $params"
}

trait OauthResponse
case class OauthRedirect(uri: String, params: Map[String, String], paramsAsUrlFragment: Boolean = false) extends OauthResponse
case class InitiateAuthzApproval(authzRequest: AuthzRequest, client: Oauth2Client) extends OauthResponse
case class Err(error: String, error_description: Option[String] = None, error_uri: Option[String] = None,
  @transient redirect_uri: Option[String] = None, @transient status_code: Int = StatusCodes.BadRequest) extends ErrorResponse(error, error_description, error_uri) with OauthResponse

case class Oauth2Client(clientId: String, clientSecret: String, scope: Seq[String] = Seq(), authorizedGrantTypes: Seq[String] = Seq(),
  redirectUri: String, authorities: Seq[String] = Seq(), accessTokenValidity: Long = 3600, refreshtokenValidity: Long = 604800,
  additionalInfo: Option[String], autoapprove: Boolean = false)

case class UserId(value: String, provider: Option[String])
case class Oauth2User(id: UserId, pwd: Option[String] = None)

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

object types {
  type GrantType = String
  type ResponseType = String
  type State = String
}