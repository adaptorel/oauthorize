package oauthorize.grants

import oauthorize.utils._
import oauthorize.model._
import oauthorize.service._
import oauth2.spec.Req._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec._
import oauth2.spec.model._
import scala.concurrent.Future

trait RefreshTokenEndpoint extends Dispatcher {

  this: Oauth2Defaults with PasswordEncoder with Oauth2Store with AuthzCodeGenerator =>

  override def matches(r: OauthRequest) = {
    val res = r.path == accessTokenEndpoint &&
      r.method == "POST" &&
      r.param(Req.grant_type).exists(v => v == GrantTypes.refresh_token)
    res
  }

  def processRefreshTokenRequest(req: OauthRequest, clientAuth: Option[ClientAuthentication]): Future[Either[Err, AccessTokenResponse]] = Future {

    clientAuth match {
      case None => Left(err(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized))
      case Some(basicAuth) => getClient(basicAuth.clientId) match {
        case None => Left(err(invalid_client, "unregistered client", StatusCodes.Unauthorized))
        case Some(client) if (!passwordMatches(basicAuth.clientSecret, client.clientSecret)) => Left(err(invalid_client, "bad credentials", StatusCodes.Unauthorized))
        case Some(client) => {
          (req.param(grant_type), req.param(refresh_token)) match {
            case (Some(grantType), Some(refreshToken)) => {
              val atRequest = RefreshTokenRequest(grantType, refreshToken)
              processRefreshTokenRequest(atRequest, client)
            } case _ => Left(err(invalid_request, s"mandatory: $grant_type, $refresh_token"))
          }
        }
      }
    }
  }

  private def processRefreshTokenRequest(refreshTokenRequest: RefreshTokenRequest, oauthClient: Oauth2Client): Either[Err, AccessTokenResponse] = {
    import oauth2.spec.AccessTokenErrors._

    getRefreshToken(refreshTokenRequest.refreshToken) match {
      case None => Left(err(invalid_grant, "invalid refresh token"))
      case Some(refreshToken) => {
        refreshTokenRequest.getError(oauthClient) match {
          case Some(error) => Left(error)
          case None if (refreshToken.isExpired) => Left(err(invalid_grant, "refresh token expired"))
          case None => {
            /*
             * TODO do we care about any previously stored data since he's started
             * the flow from the beginning, with the authorization code and everything?
             */
            val accessToken = generateAccessToken(oauthClient, refreshToken.tokenScope, refreshToken.userId)
            val stored = storeTokens(AccessAndRefreshTokens(accessToken, None), oauthClient)
            val response = AccessTokenResponse(stored.accessToken.value, stored.refreshToken.map(_.value), TokenType.bearer, stored.accessToken.validity, refreshToken.tokenScope.mkString(ScopeSeparator))
            Right(response)
          }
        }
      }
    }
  }
}