package controllers

import play.api._
import play.api.mvc._
import oauth2.spec.TokenType._
import oauth2.spec.Req._
import oauth2.spec.GrantTypes._
import oauth2.spec.AuthzErrors._
import oauth2.spec.model._
import oauthze.model._
import oauthze.utils._
import play.api.libs.json.JsValue
import play.api.libs.json.Json
import play.api.libs.json.Json.toJson
import oauthze.service._
import oauth2.spec.StatusCodes
import java.io.StringWriter
import oauth2.spec.TokenType
import scala.collection.immutable.ListMap
import scala.collection.immutable.SortedMap
import scala.collection.immutable.TreeMap

trait AuthorizationCodeAndImplicitGrants extends RenderingUtils {

  this: OauthClientStore with AuthzCodeGenerator with UserApproval =>

  import json._
  import authzform._

  def authorize = Action { implicit request =>
    val req = AuthzReqForm.bindFromRequest.discardingErrors.get

    (req.client_id, req.response_type, req.redirect_uri, req.scope) match {
      case (Some(clientId), Some(responseType), Some(redirectUri), Some(authzScope)) => {
        getClient(clientId) match {
          case None => err(invalid_request, "unregistered client")
          case Some(client) => {
            val authzRequest = AuthzRequest(clientId, responseType, redirectUri, authzScope.split(ScopeSeparator).toSeq, client.autoapprove, req.state)
            authzRequest.getError(client) match {
              case Some(err) => err
              case None => processAuthzRequest(authzRequest, client) match {
                case Left(err) => err
                case Right(resp) => resp match {
                  case authzResponse: AuthzCodeResponse => respondWith(authzResponse, client)
                  case implicitResponse: ImplicitResponse => renderImplicitResponse(implicitResponse, client)
                  case _ => throw new IllegalStateException("Shouldn't have ever got here")
                }
              }
            }
          }
        }
      }
      case _ => err(invalid_request, s"mandatory: $client_id, $response_type, $redirect_uri, $scope")
    }
  }

  private def renderImplicitResponse(implicitResponse: ImplicitResponse, client: Oauth2Client) = {
    import oauth2.spec.AccessTokenResponse._
    val params = ListMap[String, Any]() +
      (access_token -> implicitResponse.access_token) +
      (token_type -> TokenType.bearer) +
      (expires_in -> implicitResponse.expires_in) +
      (scope -> implicitResponse.scope) +
      (state -> implicitResponse.state)
    Redirect(encodedQueryString(client.redirectUri, params, "#"), Map(), 302)
  }

  private def respondWith(authzResponse: AuthzCodeResponse, client: Oauth2Client) = {
    val authzRequest = getAuthzRequest(authzResponse.code).get
    if (authzRequest.approved) {
      approved(authzResponse.code, authzRequest.state, client)
    } else {
      initiateApproval(authzResponse.code, authzRequest, client)
    }
  }

  private def processAuthzRequest[A](authzRequest: AuthzRequest, oauthClient: Oauth2Client)(implicit request: Request[A]): Either[Err, Oauth2Response] = {
    val grantType = determineGrantType(authzRequest)

    if (!oauthClient.authorizedGrantTypes.contains(grantType)) {
      Left(err(unsupported_response_type, "unsupported grant type"))
    } else {
      if (grantType == authorization_code) {
        val authzCode = generateCode(authzRequest)
        storeAuthzCode(authzCode, authzRequest, oauthClient)
        Right(AuthzCodeResponse(authzCode, authzRequest.state))
      } else {
        val token = generateAccessToken(authzRequest, oauthClient)
        val stored = storeImplicitToken(token, oauthClient)
        val expiresIn = stored.validity
        Right(ImplicitResponse(stored.value, bearer, expiresIn, authzRequest.authScope.mkString(ScopeSeparator), authzRequest.state))
      }
    }
  }

  import oauth2.spec.ResponseType
  private def determineGrantType(authzRequest: AuthzRequest) = {
    authzRequest.responseType match {
      case "code" => authorization_code
      case "token" => implic1t
      case _ => throw new IllegalStateException(s"Should have only ${ResponseType.code} and ${ResponseType.token} authorization request response types")
    }
  }

  object authzform {
    import play.api.data._
    import play.api.data.Forms._
    case class AuthzReq(client_id: Option[String], response_type: Option[String], redirect_uri: Option[String], scope: Option[String], state: Option[String])
    val AuthzReqForm = Form(
      mapping(
        "client_id" -> optional(text),
        "response_type" -> optional(text),
        "redirect_uri" -> optional(text),
        "scope" -> optional(text),
        "state" -> optional(text))(AuthzReq.apply)(AuthzReq.unapply))
  }
}