package controllers

import oauthze.service._
import oauth2.spec.StatusCodes
import play.api.mvc._
import play.api.libs.json._
import oauth2.spec.model._
import oauthze.model.Err

trait Oauth extends InMemoryOauthClientStore with DefaultAuthzCodeGenerator with BCryptPasswordEncoder

object Application extends Oauth with AuthorizationCodeAndImplicitGrants with UserApproval with AccessTokenEnpoint

object json {
  implicit val AuthzCodeResponseFormat = Json.format[AuthzCodeResponse]
  implicit val ImplicitResponseFormat = Json.format[ImplicitResponse]
  implicit val AccessTokenResponseFormat = Json.format[AccessTokenResponse]
  implicit object ErrorsFormat extends Format[Err] {
    def reads(json: JsValue): JsResult[Err] = Json.reads[Err].reads(json)
    def writes(err: Err): JsValue = Json.writes[Err].writes(err) - "status_code"
  }

  implicit def errToJsValue(err: Err) = Json.toJson(err)
}

trait RenderingUtils extends Controller {

  import json._

  implicit def renderAccessTokenResponse(r: AccessTokenResponse): Result = Ok(Json.toJson(r))
  implicit def renderErrorAsResult(err: Err): Result = {
    err.status_code match {
      case StatusCodes.BadRequest => BadRequest(Json.toJson(err))
      case StatusCodes.Redirect => {
        err.redirect_uri.map { url =>
          val c = Json.toJson(err)
          val params = c.as[Map[String, JsValue]].map(pair => (pair._1, Seq(pair._2.as[String])))
          Redirect(url, params, err.status_code)
        } getOrElse (BadRequest(Json.toJson(err)))
      }
      case StatusCodes.Unauthorized => Unauthorized(Json.toJson(err))
      case _ => throw new UnsupportedOperationException("Only error status codes should be rendered by the error handler")
    }
  }
}