package oauthorize.model

import oauth2.spec.StatusCodes
import oauth2.spec.model.ErrorResponse

import types._

/**
 * Validity expressed in seconds
 * Created is timesptamp milliseconds
 */
sealed trait Expirable {
  def validity: Long
  def created: Long
  def isExpired = created + validity * 1000 < System.currentTimeMillis
  def validityRemaining = created / 1000 + validity - System.currentTimeMillis / 1000
}

case class AuthzRequest(
  code: Option[String],  
  clientId: String,
  responseType: ResponseType,
  redirectUri: String,
  authScope: Seq[String],
  approved: Boolean,
  validity: Long,
  created: Long,
  state: Option[State] = None,
  user: Option[Oauth2User] = None) extends Expirable with AuthzRequestValidation

case class AccessTokenRequest(
  grantType: GrantType,
  authzCode: String,
  redirectUri: String,
  clientId: Option[String]) extends AccessTokenRequestValidation

case class RefreshTokenRequest(
  grantType: GrantType,
  refreshToken: String) extends RefreshTokenRequestValidation

case class ClientCredentialsRequest(
  grantType: GrantType,  
  client: Oauth2Client,
  authScope: Option[String]) extends ClientCredentialsRequestValidation

case class ResourceOwnerCredentialsRequest(
  grantType: GrantType,
  username: String,
  password: String,
  authScope: Seq[String]) extends ResourceOwnerCredentialsRequestValidation

abstract class Token {
  def value: String
  def clientId: String
  def tokenScope: Seq[String]
  def validity: Long
  def created: Long
  def userId: Option[UserId]
}

case class AccessToken(
  value: String,
  clientId: String,
  tokenScope: Seq[String],
  validity: Long,
  created: Long,
  userId: Option[UserId]) extends Token with Expirable

case class RefreshToken(
  value: String,
  clientId: String,
  tokenScope: Seq[String],
  validity: Long,
  created: Long,
  userId: Option[UserId]) extends Token with Expirable

case class AccessAndRefreshTokens(
  accessToken: AccessToken,
  refreshToken: Option[RefreshToken] = None)

trait OauthRequest {
  def path: String
  def param(key: String): Option[String]
  def header(key: String): Option[String]
  def method: String
  def params: Map[String, String]
  override def toString = s"$method '$path' $params"
}

trait OauthResponse
case class OauthRedirect(
  uri: String,
  params: Map[String, String],
  paramsAsUrlFragment: Boolean = false) extends OauthResponse

case class InitiateAuthzApproval(
  authzRequest: AuthzRequest,
  client: Oauth2Client,
  csrfToken: Option[String] = None) extends OauthResponse

case class Err(
  error: String,
  error_description: Option[String] = None,
  error_uri: Option[String] = None,
  @transient redirect_uri: Option[String] = None,
  @transient status_code: Int = StatusCodes.BadRequest) extends ErrorResponse(error, error_description, error_uri) with OauthResponse

case class Oauth2Client(
  clientId: String,
  secretInfo: SecretInfo,
  scope: Seq[String] = Seq(),
  authorizedGrantTypes: Seq[String] = Seq(),
  redirectUri: String,
  authorities: Seq[String] = Seq(),
  accessTokenValidity: Long = 3600,
  refreshTokenValidity: Long = 604800,
  additionalInfo: Option[String],
  autoapprove: Boolean = false) {

  def invalidScopes(sc: Option[String]): Boolean = sc.exists(v => invalidScopes(v.split(" ")))
  def invalidScopes(sc: Seq[String]): Boolean = sc.foldLeft(false) { (acc, curr) => acc || !scope.contains(curr) }
}

case class UserId(value: String, provider: Option[String])
case class SecretInfo(secret: String, salt: Option[String] = None)
case class Oauth2User(id: UserId, pwd: Option[SecretInfo] = None)

case class ClientAuthentication(clientId: String, clientSecret: String)

object types {
  type GrantType = String
  type ResponseType = String
  type State = String
}