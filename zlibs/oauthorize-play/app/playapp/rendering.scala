package oauthorize.playapp.grants

import play.api.libs.json._
import play.api.mvc._
import play.api.libs.concurrent.Execution.Implicits.defaultContext

import oauth2.spec.model._
import oauth2.spec._
import oauthorize.model._
import oauthorize.utils._
import oauthorize.grants.UserApproval
import scala.concurrent.Future

object json {
  implicit val AuthzCodeResponseFormat = Json.format[AuthzCodeResponse]
  implicit val AccessTokenResponseFormat = Json.format[AccessTokenResponse]
  implicit val UserIdFormat = Json.format[UserId]
  implicit val SecretInfoFormat = Json.format[SecretInfo]
  implicit val Oauth2UserFormat = Json.format[Oauth2User]
  implicit val AuthzRequestFormat = Json.format[AuthzRequest]
  implicit object ErrorsFormat extends Format[Err] {
    def reads(json: JsValue): JsResult[Err] = Json.reads[Err].reads(json)
    def writes(err: Err): JsValue = Json.writes[Err].writes(err) - "status_code" - "redirect_uri"
  }
  implicit def errToJsValue(err: Err) = Json.toJson(err)
}

trait RenderingUtils extends Controller {

  this: Oauth2Config =>

  import json._

  implicit def renderAccessTokenResponse(r: AccessTokenResponse): SimpleResult = Ok(Json.toJson(r))
  implicit def renderErrorAsResult(err: Err): SimpleResult = {
    err.status_code match {
      case StatusCodes.Redirect => {
        err.redirect_uri.map { url =>
          val c = Json.toJson(err)
          val params = c.as[Map[String, JsValue]].map(pair => (pair._1, Seq(pair._2.as[String])))
          Redirect(url, params, err.status_code)
        } getOrElse (BadRequest(Json.toJson(err)))
      }
      case StatusCodes.BadRequest => BadRequest(Json.toJson(err))
      case StatusCodes.Unauthorized => Unauthorized(Json.toJson(err))
      case StatusCodes.InternalServerError => InternalServerError(Json.toJson(err))
      case _ => throw new UnsupportedOperationException("Only error status codes should be rendered by the error handler")
    }
  }

  implicit def transformReponse(response: OauthResponse) = response match {
    case a: InitiateAuthzApproval => Redirect(userApprovalEndpoint, Map(UserApproval.AuthzRequestKey -> authzParam(a.authzRequest), UserApproval.AutoApproveKey -> Seq(a.client.autoapprove.toString)), 302)
    case r: OauthRedirect =>
      if (r.paramsAsUrlFragment)
        Redirect(encodedQueryString(r.uri, r.params, "#"), Map(), 302)
      else
        Redirect(r.uri, r.params.map(tuple => (tuple._1 -> Seq(tuple._2))), 302)
  }

  private def authzParam(authzReq: AuthzRequest) = Seq(Json.stringify(Json.toJson(authzReq)))
}
