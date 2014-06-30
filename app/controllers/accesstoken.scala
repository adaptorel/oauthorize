package controllers

import play.api.mvc.Controller
import play.api._
import play.api.mvc._
import oauthze.utils._
import oauthze.service._
import oauthze.model._
import oauth.spec.Req._
import oauth.spec.GrantTypes._
import oauth.spec.model._
import oauth.spec.TokenType.bearer
import play.api.libs.json.JsValue
import play.api.libs.json.Json

trait AccessToken extends Controller {

  this: OauthClientStore with AuthzCodeGenerator with PasswordEncoder =>

  import json._

  def accessToken() = Action { implicit request =>

    import oauth.spec.AccessTokenErrors._
    import accesstoken._

    BasicAuthentication(request) match {
      case None => Unauthorized(err(unauthorized_client, "unauthorized client"))
      case Some(basicAuth) => getClient(basicAuth.clientId) match {
        case None => Unauthorized(err(invalid_client, "unregistered client"))
        case Some(client) if (client.clientSecret != encodePassword(basicAuth.clientSecret)) => Unauthorized(err(invalid_client, "bad credentials"))
        case Some(client) => {
          val form = AccTokenReqForm.bindFromRequest.discardingErrors.get
          for {
            grantType <- form.grant_type
            authzCode <- form.code
          } yield {
            val atRequest = AccessTokenRequest(grantType, authzCode, form.redirect_uri, form.client_id)
            processAccessTokenRequest(atRequest, client) match {
              case Left(err) => BadRequest(err)
              case Right(res) => Ok(res)
            }
          }
        } getOrElse BadRequest(err(invalid_request, s"mandatory: $grant_type, $code"))
      }
    }
  }

  private def processAccessTokenRequest[A](accessTokenRequest: AccessTokenRequest, oauthClient: OauthClient)(implicit request: Request[A]): Either[JsValue, JsValue] = {

    import oauth.spec.AccessTokenErrors._

    getAuthzRequest(accessTokenRequest.authzCode) match {
      case None => Left(err(invalid_request, "invalid authorization code"))
      case Some(authzRequest) => {
        accessTokenRequest.getError(authzRequest, oauthClient.clientId) match {
          case Some(error) => Left(error)
          case None => {
            /*
             * TODO do we care about any previously stored data since he's started
             * the flow from the beginning, with the authorization code and everything?
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

  object accesstoken {
    import play.api.data._
    import play.api.data.Forms._
    case class AccTokenReq(grant_type: Option[String], code: Option[String], redirect_uri: Option[String], client_id: Option[String])
    val AccTokenReqForm = Form(
      mapping(
        "grant_type" -> optional(text),
        "code" -> optional(text),
        "redirect_uri" -> optional(text),
        "client_id" -> optional(text))(AccTokenReq.apply)(AccTokenReq.unapply))
  }
}