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
import oauthze.service._

trait Authorize extends Controller {

  this: OauthClientStore with AuthzCodeGenerator with UserApproval =>

  import json._
  import authzform._
  type JsErr = JsValue

  def authorize = Action { implicit request =>
    val req = AuthzReqForm.bindFromRequest.discardingErrors.get
    
    (req.client_id, req.response_type) match {
      case (Some(clientId), Some(responseType)) => {
        getClient(clientId) match {
          case None => BadRequest(err(invalid_request, "unregistered client"))
          case Some(client) => {
            val authzRequest = AuthzRequest(clientId, responseType, req.state, req.redirect_uri, req.scope.map(_.split(ScopeSeparator).toSeq).getOrElse(Seq()), client.autoapprove)
            processAuthzRequest(authzRequest, client) match {
              case Left(err) => BadRequest(err)
              case Right(resp) => resp match {
                case authzResponse: AuthzCodeResponse => respondWith(authzResponse, client)
                case implicitResponse: ImplicitResponse => Ok(Json.toJson(implicitResponse))
                case _ => throw new IllegalStateException("Shouldn't have ever got here")
              }
            }
          }
        }
      }
      case _ => BadRequest(err(invalid_request, s"mandatory: $client_id, $response_type"))
    }
  }

  private def respondWith(authzResponse: AuthzCodeResponse, client: OauthClient) = {
    val authzRequest = getAuthzRequest(authzResponse.code).get
    
    if (authzRequest.approved) {
      approved(authzResponse.code, authzRequest.state, client)
    } else {
      initiateApproval(authzResponse.code, authzRequest, client)
    }
  }

  private def processAuthzRequest[A](authzRequest: AuthzRequest, oauthClient: OauthClient)(implicit request: Request[A]): Either[JsErr, Oauth2Response] = {
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
        Right(ImplicitResponse(stored.value, bearer, expiresIn, authzRequest.scope.mkString(ScopeSeparator), authzRequest.state))
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
    case class AuthzReq(client_id: Option[String], response_type: Option[String], redirect_uri: Option[String], state: Option[String], scope: Option[String])
    val AuthzReqForm = Form(
      mapping(
        "client_id" -> optional(text),
        "response_type" -> optional(text),
        "redirect_uri" -> optional(text),
        "state" -> optional(text),
        "scope" -> optional(text))(AuthzReq.apply)(AuthzReq.unapply))
  }
}