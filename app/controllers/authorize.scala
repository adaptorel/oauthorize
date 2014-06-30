package controllers

import play.api.mvc.Controller
import play.api._
import play.api.mvc._
import oauth.spec.TokenType._
import oauth.spec.Req._
import oauth.spec.GrantTypes._
import oauth.spec.AuthzErrors._
import oauth.spec.model._
import oauthze.model._
import oauthze.utils._
import play.api.libs.json.JsValue
import play.api.libs.json.Json
import oauthze.service._

trait Authorize extends Controller {

  this: OauthClientStore with AuthzCodeGenerator =>
  
  import json._
  import play.api.mvc.Controller

  def authorize() = Action { implicit request =>
    {
      for {
        clientId <- request.getQueryString(client_id)
        responseType <- request.getQueryString(response_type)
      } yield {
        getClient(clientId) match {
          case None => BadRequest(err(invalid_request, "unregistered client"))
          case Some(client) => {
            val authzRequest = AuthzRequest(clientId, responseType, request.getQueryString(state), request.getQueryString(redirect_uri), request.getQueryString(scope).map(_.split(ScopeSeparator).toSeq).getOrElse(Seq()), client.autoapprove)
            processAuthzRequest(authzRequest, client) match {
              case Left(err) => BadRequest(err)
              case Right(res) => {
                //TODO this fails fast for ImplicitResponse
                val authzCode = (res \ code).as[String]
                val authzRequest = getAuthzRequest(authzCode).get
                if (authzRequest.approved) {
                  val params = res.as[Map[String, JsValue]].map(pair => (pair._1, Seq(pair._2.as[String])))
                  Redirect(s"${client.redirectUri}", params, 302)
                } else {
                  //Redirect("/oauth/approve").withSe
                  throw new UnsupportedOperationException("User approval not yet implemeted")
                }
              }
            }
          }
        }
      }
    } getOrElse BadRequest(err(invalid_request, s"mandatory: $client_id, $response_type"))
  }

  private def processAuthzRequest[A](authzRequest: AuthzRequest, oauthClient: OauthClient)(implicit request: Request[A]): Either[JsValue, JsValue] = {

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

  import oauth.spec.ResponseType
  private def determineGrantType(authzRequest: AuthzRequest) = {
    authzRequest.responseType match {
      case "code" => authorization_code
      case "token" => implic1t
      case _ => throw new IllegalStateException(s"Should have only ${ResponseType.code} and ${ResponseType.token} authorization request response types")
    }
  }
}