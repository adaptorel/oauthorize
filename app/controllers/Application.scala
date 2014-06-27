package controllers

import play.api._
import play.api.mvc._
import utils._
import utils.Req._
import utils.Error._
import utils.AuthzErrors._
import utils.GrantType._
import utils.TokenType._
import client._
import play.api.libs.json.JsValue
import play.api.libs.json.Json
import java.security.MessageDigest
import java.util.UUID
import org.apache.commons.codec.binary.Hex
import play.api.libs.json.Format

object utils {

  type GrantType = String
  type ResponseType = String
  type State = String

  val ScopeSeparator = " "

  object GrantType {
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
  }

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

  object TokenType {
    val bearer = "bearer"
  }

  def err(err: String): JsValue = {
    Json.obj(error -> err)
  }

  def err(err: String, desc: String): JsValue = {
    Json.obj(error -> err, error_description -> desc)
  }

  def sha256UUID() = {
    new String(Hex.encodeHex(MessageDigest.getInstance("SHA-256").digest(UUID.randomUUID.toString.getBytes)))
  }
}

trait AuthzResponse
case class AuthzCodeResponse(code: String, state: Option[String]) extends AuthzResponse
case class ImplicitResponse(access_token: String, token_type: String = bearer, expires_in: Long, scope: Seq[String], state: Option[String]) extends AuthzResponse
case class AuthzRequest(clientId: String, responseType: ResponseType, state: Option[State], redirectUri: Option[String], scope: Seq[String]) extends AuthzRequestValidation

abstract class Token(value: String, validity: Long, created: Long, client_id: String)
case class AccessToken(value: String, client_id: String, validity: Long, created: Long, scope: Seq[String]) extends Token(value, validity, created, client_id)
case class RefreshToken(value: String, client_id: String, validity: Long, created: Long) extends Token(value, validity, created, client_id)

object json {
  implicit val AuthzCodeResponseFormat = Json.format[AuthzCodeResponse]
  implicit val ImplicitResponseFormat = Json.format[ImplicitResponse]
}

object client {
  case class OauthClient(clientId: String, clientSecret: String, scope: Seq[String] = Seq(), authorizedGrantTypes: Seq[String] = Seq(),
    redirectUri: String, authorities: Seq[String] = Seq(), accessTokenValidity: Long = 3600, refreshtokenValidity: Long = 604800,
    additionalInfo: Option[String], autoapprove: Boolean = false)

  trait OauthClientStore {
    def saveClient(client: OauthClient)
    def getClient(clientId: String): Option[OauthClient]
    def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: OauthClient)
    def storeAuthzToken(token: AccessToken, authzRequest: AuthzRequest, oauthClient: OauthClient): AccessToken
  }

  trait InMemoryOauthClientStore extends OauthClientStore {
    private val oauthClientStore = scala.collection.mutable.Map[String, OauthClient]()
    private val authzCodeStore = scala.collection.mutable.Map[String, AuthzRequest]()
    private val authzTokenStore = scala.collection.mutable.Map[String, AccessToken]()
    override def saveClient(client: OauthClient) = oauthClientStore.put(client.clientId, client)
    override def getClient(clientId: String) = oauthClientStore.get(clientId)
    override def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: OauthClient) = { authzCodeStore.put(authzCode, authzRequest) }
    override def storeAuthzToken(token: AccessToken, authzRequest: AuthzRequest, oauthClient: OauthClient): AccessToken = { authzTokenStore.put(token.value, token); token }
  }

  case class AccessAndRefreshTokens(access_token: String, refresh_token: Option[String])
  case class StoredAccessAndRefreshTokens(accessToken: AccessToken, refreshToken: Option[RefreshToken])

  trait AuthzCodeGenerator {
    def generateCode(authzRequest: AuthzRequest): String
    def generateToken(authzRequest: AuthzRequest, oauthClient: OauthClient): AccessToken
  }

  trait DefaultAuthzCodeGenerator extends AuthzCodeGenerator {
    override def generateCode(authzRequest: AuthzRequest) = sha256UUID
    //no refresh token for authorization request token / implicit grant
    override def generateToken(authzRequest: AuthzRequest, oauthClient: OauthClient) = AccessToken(sha256UUID, oauthClient.clientId, oauthClient.accessTokenValidity, System.currentTimeMillis, authzRequest.scope)
  }
}

trait Oauth extends InMemoryOauthClientStore with DefaultAuthzCodeGenerator

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
      case Some(authzRequest: AuthzRequest) => processAuthzRequest(request, authzRequest) match {
        case Left(err) => BadRequest(err)
        case Right(res) => Ok(res)
      }
      case _ => BadRequest(err(invalid_request, s"mandatory: $client_id, $response_type"))
    }
  }

  private def processAuthzRequest[A](request: Request[A], authzRequest: AuthzRequest): Either[JsValue, JsValue] = {
    import ResponseType._
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
            val token = generateToken(authzRequest, oauthClient)
            val stored = storeAuthzToken(token, authzRequest, oauthClient)
            val expiresIn = stored.validity
            Right(Json.toJson(ImplicitResponse(stored.value, bearer, expiresIn, authzRequest.scope, authzRequest.state)))
          }
        }
      }
    }
  }

  private def determineGrantType(authzRequest: AuthzRequest) = {
    import ResponseType._
    authzRequest.responseType match {
      case "code" => authorization_code
      case "token" => implic1t
      case _ => throw new IllegalStateException(s"Should have only $code and $token authorization request response types")
    }
  }

  private def validateAuthorizationRequest[A](request: Request[A], authorizationRequest: AuthzRequest): Either[JsValue, Any] = {
    Right()
  }

}

trait AuthzRequestValidation {
  this: AuthzRequest =>

  def getError: Option[JsValue] = {
    errClientId orElse
      errResponseType
  }

  private def errClientId = {
    errForEmpty(clientId, err(AuthzErrors.invalid_request, s"mandatory: $client_id"))
  }

  private def errResponseType = {
    import ResponseType._
    errForEmpty(responseType, err(invalid_request, s"mandatory: $response_type")) orElse {
      responseType match {
        case ResponseType.code | ResponseType.token => None
        case _ => Some(err(invalid_request, s"mandatory: $response_type in ['$code','$token']"))
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