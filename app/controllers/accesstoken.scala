package controllers

import play.api.mvc.Controller
import play.api._
import play.api.mvc._
import oauthze.utils._
import oauthze.service._
import oauthze.model._
import oauth2.spec.Req._
import oauth2.spec.GrantTypes._
import oauth2.spec.model._
import oauth2.spec.TokenType.bearer
import play.api.libs.json.JsValue
import play.api.libs.json.Json
import oauth2.spec.StatusCodes

trait AccessTokenEnpoint extends Controller with RenderingUtils {

  this: OauthClientStore with AuthzCodeGenerator with PasswordEncoder =>

  import json._

  def accessToken = Action { implicit request =>

    import oauth2.spec.AccessTokenErrors._
    import accesstoken._

    BasicAuthentication(request) match {
      case None => err(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized)
      case Some(basicAuth) => getClient(basicAuth.clientId) match {
        case None => err(invalid_client, "unregistered client", StatusCodes.Unauthorized)
        case Some(client) if (!passwordMatches(basicAuth.clientSecret, client.clientSecret)) => err(invalid_client, "bad credentials", StatusCodes.Unauthorized)
        case Some(client) => {
          val form = AccTokenReqForm.bindFromRequest.discardingErrors.get
          (form.grant_type, form.code, form.redirect_uri) match {
            case (Some(grantType), Some(authzCode), Some(redirectUri)) => {
              val atRequest = AccessTokenRequest(grantType, authzCode, redirectUri, form.client_id)
              processAccessTokenRequest(atRequest, client) match {
                case Left(err) => err
                case Right(res) => res
              }
            } case _ => err(invalid_request, s"mandatory: $grant_type, $code, $redirect_uri")
          }
        }
      }
    }
  }

  private def processAccessTokenRequest[A](accessTokenRequest: AccessTokenRequest, oauthClient: Oauth2Client)(implicit request: Request[A]): Either[Err, AccessTokenResponse] = {
    import oauth2.spec.AccessTokenErrors._

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
            val response = AccessTokenResponse(stored.accessToken.value, stored.refreshToken.map(_.value), bearer, stored.accessToken.validity, authzRequest.authScope.mkString(ScopeSeparator))
            Right(response)
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