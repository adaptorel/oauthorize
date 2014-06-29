package controllers

import play.api._
import play.api.mvc._
import utils._
import utils.Req._
import utils.Error._
import utils.AuthzErrors._
import utils.GrantTypes._
import utils.TokenType._
import client._
import play.api.libs.json.JsValue
import play.api.libs.json.Json
import java.security.MessageDigest
import java.util.UUID
import org.apache.commons.codec.binary.Hex
import play.api.libs.json.Format
import org.apache.commons.codec.binary.Base64

object utils {

  type GrantType = String
  type ResponseType = String
  type State = String

  val ScopeSeparator = " "

  object GrantTypes {
    val authorization_code = "authorization_code"
    val password = "password"
    val client_credentials = "client_credentials"
    val refresh_token = "refresh_token"
    val implic1t = "implicit"
  }

  object Req {
    val client_id = "client_id"
    val state = "state"
    val response_type = "response_type"
    val redirect_uri = "redirect_uri"
    val scope = "scope"
    val grant_type = "grant_type"
    val code = "code"
  }

  /**
   * Do not ever import ResponseType._ as code clashes with Req.code
   * As ResponseType has a much more limited usage scope, always use
   * ResponseType.code and ResponseType.token
   */
  object ResponseType {
    val code = "code"
    val token = "token"
  }

  object Error {
    val error = "error"
    val error_description = "error_description"
    val error_uri = "error_uri"
  }

  object AuthzErrors {
    val invalid_request = "invalid_request"
    val unauthorized_client = "unauthorized_client"
    val access_denied = "access_denied"
    val unsupported_response_type = "unsupported_response_type"
    val invalid_scope = "invalid_scope"
    val server_error = "server_error"
    val temporarily_unavailable = "temporarily_unavailable"
  }

  object AccessTokenErrors {
    val invalid_request = "invalid_request"
    val invalid_client = "invalid_client"
    val invalid_grant = "invalid_grant"
    val unauthorized_client = "unauthorized_client"
    val unsupported_response_type = "unsupported_response_type"
    val invalid_scope = "invalid_scope"
    val server_error = "server_error"
    val temporarily_unavailable = "temporarily_unavailable"
  }

  object TokenType {
    val bearer = "bearer"
  }

  def err(err: String): JsValue = {
    Json.obj(error -> err)
  }

  def err(err: String, desc: String): JsValue = {
    Json.obj(error -> err, error_description -> desc)
  }

  private def sha256UUID() = {
    sha256(UUID.randomUUID.toString)
  }

  def sha256(value: String) = {
    new String(Hex.encodeHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes("UTF-8"))))
  }

  case class BasicAuthentication(clientId: String, clientSecret: String)
  object BasicAuthentication {

    def apply[A](request: Request[A]) = {
      request.headers.get("Authorization").filter(_.startsWith("Basic ")) flatMap { authHeader =>
        BasicAuthentication.fromBase64(authHeader.replaceAll("Basic ", ""))
      }
    }

    private def fromBase64(base64: String): Option[BasicAuthentication] = {
      val clientIdAndPassword = new String(Base64.decodeBase64(base64.getBytes("UTF-8"))).split(":")
      if (clientIdAndPassword.length == 2) {
        Some(BasicAuthentication(clientIdAndPassword(0), clientIdAndPassword(1)))
      } else None
    }
  }
}

trait PasswordEncoder {
  def encodePassword(pwd: String): String
  def passwordMatches(rawPassword: String, encodedPassword: String): Boolean
}

trait Sha256PasswordEncoder extends PasswordEncoder {
  override def encodePassword(pwd: String): String = sha256(pwd)
  def passwordMatches(rawPassword: String, encodedPassword: String): Boolean = sha256(rawPassword) == encodedPassword
}

trait AuthzResponse
case class AuthzCodeResponse(code: String, state: Option[String]) extends AuthzResponse
case class ImplicitResponse(access_token: String, token_type: String = bearer, expires_in: Long, scope: String, state: Option[String]) extends AuthzResponse
case class AuthzRequest(clientId: String, responseType: ResponseType, state: Option[State], redirectUri: Option[String], scope: Seq[String]) extends AuthzRequestValidation
case class AccessTokenRequest(grantType: GrantType, authzCode: String, redirectUri: Option[String], clientId: Option[String]) extends AccessTokenRequestValidation
trait AccessResponse
case class AccessTokenResponse(access_token: String, refresh_token: Option[String], token_type: String = bearer, expires_in: Long, scope: String) extends AccessResponse

abstract class Token(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long)
case class AccessToken(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long) extends Token(value, client_id, scope, validity, created)
case class RefreshToken(value: String, client_id: String, scope: Seq[String], validity: Long, created: Long) extends Token(value, client_id, scope, validity, created)

object json {
  implicit val AuthzCodeResponseFormat = Json.format[AuthzCodeResponse]
  implicit val ImplicitResponseFormat = Json.format[ImplicitResponse]
  implicit val AccessTokenResponseFormat = Json.format[AccessTokenResponse]
}

object client {
  case class OauthClient(clientId: String, clientSecret: String, scope: Seq[String] = Seq(), authorizedGrantTypes: Seq[String] = Seq(),
    redirectUri: String, authorities: Seq[String] = Seq(), accessTokenValidity: Long = 3600, refreshtokenValidity: Long = 604800,
    additionalInfo: Option[String], autoapprove: Boolean = false)

  trait OauthClientStore {
    def saveClient(client: OauthClient): OauthClient
    def getClient(clientId: String): Option[OauthClient]
    def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: OauthClient)
    def getAuthzRequest(authzCode: String): Option[AuthzRequest]
    def storeImplicitToken(token: AccessToken, oauthClient: OauthClient): AccessToken
    def storeAccessAndRefreshTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: OauthClient): AccessAndRefreshTokens
    def getAuthDataForClient(clientId: String): Option[AccessAndRefreshTokens]
  }

  trait InMemoryOauthClientStore extends OauthClientStore {
    private val oauthClientStore = scala.collection.mutable.Map[String, OauthClient]()
    private val authzCodeStore = scala.collection.mutable.Map[String, AuthzRequest]()
    private val implicitTokenStore = scala.collection.mutable.Map[String, AccessToken]()
    private val accessTokenStore = scala.collection.mutable.Map[String, AccessAndRefreshTokens]()

    override def saveClient(client: OauthClient) = { oauthClientStore.put(client.clientId, client); client }
    override def getClient(clientId: String) = oauthClientStore.get(clientId)
    override def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: OauthClient) = { authzCodeStore.put(authzCode, authzRequest) }
    override def getAuthzRequest(authzCode: String) = authzCodeStore.get(authzCode)
    override def storeImplicitToken(token: AccessToken, oauthClient: OauthClient): AccessToken = { implicitTokenStore.put(token.value, token); token }
    override def storeAccessAndRefreshTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: OauthClient) = { accessTokenStore.put(oauthClient.clientId, accessAndRefreshTokens); accessAndRefreshTokens }
    override def getAuthDataForClient(clientId: String) = accessTokenStore.get(clientId)
  }

  case class AccessAndRefreshTokens(accessToken: AccessToken, refreshToken: Option[RefreshToken])

  trait AuthzCodeGenerator {
    def generateCode(authzRequest: AuthzRequest): String
    def generateAccessToken(authzRequest: AuthzRequest, oauthClient: OauthClient): AccessToken
    def generateRefreshToken(authzRequest: AuthzRequest, oauthClient: OauthClient): RefreshToken
  }

  trait DefaultAuthzCodeGenerator extends AuthzCodeGenerator {
    this: PasswordEncoder =>
    override def generateCode(authzRequest: AuthzRequest) = newToken
    //no refresh token for authorization request token / implicit grant
    override def generateAccessToken(authzRequest: AuthzRequest, oauthClient: OauthClient) = AccessToken(newToken, oauthClient.clientId, authzRequest.scope, oauthClient.accessTokenValidity, System.currentTimeMillis)
    override def generateRefreshToken(authzRequest: AuthzRequest, oauthClient: OauthClient) = RefreshToken(newToken, oauthClient.clientId, authzRequest.scope, oauthClient.accessTokenValidity, System.currentTimeMillis)
    def newToken = encodePassword(UUID.randomUUID().toString)
  }
}

trait Oauth extends InMemoryOauthClientStore with DefaultAuthzCodeGenerator with Sha256PasswordEncoder

object Application extends Controller with Oauth {

  import json._

  def authorize() = Action { implicit request =>
    {
      for {
        clientId <- request.getQueryString(client_id)
        responseType <- request.getQueryString(response_type)
      } yield {
        AuthzRequest(clientId, responseType, request.getQueryString(state), request.getQueryString(redirect_uri), request.getQueryString(scope).map(_.split(ScopeSeparator).toSeq).getOrElse(Seq()))
      }
    } match {
      case Some(authzRequest: AuthzRequest) => processAuthzRequest(authzRequest) match {
        case Left(err) => BadRequest(err)
        case Right(res) => Ok(res)
      }
      case _ => BadRequest(err(invalid_request, s"mandatory: $client_id, $response_type"))
    }
  }

  def accessToken() = Action { implicit request =>

    import AccessTokenErrors._

    BasicAuthentication(request) match {
      case None => Unauthorized(err(unauthorized_client, "unauthorized client"))
      case Some(basicAuth) => getClient(basicAuth.clientId) match {
        case None => Unauthorized(err(invalid_client, "unregistered client"))
        case Some(client) if (client.clientSecret != encodePassword(basicAuth.clientSecret)) => Unauthorized(err(invalid_client, "bad credentials"))
        case Some(client) => {
          for {
            grantType <- request.getQueryString(grant_type)
            authzCode <- request.getQueryString(code)
          } yield {
            val atRequest = AccessTokenRequest(grantType, authzCode, request.getQueryString(redirect_uri), request.getQueryString(client_id))
            processAccessTokenRequest(atRequest, client) match {
              case Left(err) => BadRequest(err)
              case Right(res) => Ok(res)
            }
          }
        } getOrElse BadRequest(err(invalid_request, s"mandatory: $grant_type, $code"))
      }
    }
  }
  
  private def processAuthzRequest[A](authzRequest: AuthzRequest)(implicit request: Request[A]): Either[JsValue, JsValue] = {

    getClient(authzRequest.clientId) match {
      case None => Left(err(invalid_request, s"unknown client: ${authzRequest.clientId}"))
      case Some(oauthClient) => {
        val grantType = determineGrantType(authzRequest)

        if (!oauthClient.authorizedGrantTypes.contains(grantType)) {
          Left(err(unsupported_response_type, "unsupported grant type"))
        } else {
          if (grantType == authorization_code) {
            val authzCode = generateCode(authzRequest)
            storeAuthzCode(authzCode, authzRequest, oauthClient)
            Right(Json.toJson(AuthzCodeResponse(authzCode, authzRequest.state)))
          } else {
            val token = generateAccessToken(authzRequest, oauthClient)
            val stored = storeImplicitToken(token, oauthClient)
            val expiresIn = stored.validity
            Right(Json.toJson(ImplicitResponse(stored.value, bearer, expiresIn, authzRequest.scope.mkString(ScopeSeparator), authzRequest.state)))
          }
        }
      }
    }
  }

  private def processAccessTokenRequest[A](accessTokenRequest: AccessTokenRequest, oauthClient: OauthClient)(implicit request: Request[A]): Either[JsValue, JsValue] = {

    import AccessTokenErrors._

    getAuthzRequest(accessTokenRequest.authzCode) match {
      case None => Left(err(invalid_request, "invalid authorization code"))
      case Some(authzRequest) => {
        accessTokenRequest.getError(authzRequest, oauthClient.clientId) match {
          case Some(error) => Left(error)
          case None => {
            /*
             * TODO do we care about any previously stored data since he's started
             * the flow from the beginning, with the authorization code?
             */
            val accessToken = generateAccessToken(authzRequest, oauthClient)
            val refreshToken = if (oauthClient.authorizedGrantTypes.contains(refresh_token)) {
              Some(generateRefreshToken(authzRequest, oauthClient))
            } else None
            val stored = storeAccessAndRefreshTokens(AccessAndRefreshTokens(accessToken, refreshToken), oauthClient)
            val response = AccessTokenResponse(stored.accessToken.value, stored.refreshToken.map(_.value), bearer, stored.accessToken.validity, authzRequest.scope.mkString(ScopeSeparator))
            Right(Json.toJson(response))
          }
        }
      }
    }
  }

  private def determineGrantType(authzRequest: AuthzRequest) = {

    authzRequest.responseType match {
      case "code" => authorization_code
      case "token" => implic1t
      case _ => throw new IllegalStateException(s"Should have only ${ResponseType.code} and ${ResponseType.token} authorization request response types")
    }
  }
}

trait AuthzRequestValidation {
  this: AuthzRequest =>

  import AuthzErrors._

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

  import AccessTokenErrors._

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