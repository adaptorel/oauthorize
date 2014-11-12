package oauthorize.grants

import oauthorize.utils._
import oauthorize.model._
import oauthorize.service._
import oauth2.spec.Req._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec._
import oauth2.spec.model._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext

class RefreshTokenEndpoint(
  val config: Oauth2Config,
  val store: Oauth2Store,
  val hasher: ClientSecretHasher,
  val tokens: TokenGenerator) {

  def processRefreshTokenRequest(
    req: OauthRequest,
    clientAuth: Option[ClientAuthentication])(implicit ctx: ExecutionContext): Future[Either[Err, AccessTokenResponse]] = {

    clientAuth match {
      case None => error(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized)
      case Some(basicAuth) => store.getClient(basicAuth.clientId) flatMap {
        case None => error(invalid_client, "unregistered client", StatusCodes.Unauthorized)
        case Some(client) if (!hasher.secretMatches(basicAuth.clientSecret, client.secretInfo)) => error(invalid_client, "bad credentials", StatusCodes.Unauthorized)
        case Some(client) => {
          (req.param(grant_type), req.param(refresh_token)) match {
            case (Some(grantType), Some(refreshToken)) => {
              val atRequest = RefreshTokenRequest(grantType, refreshToken)
              doProcess(atRequest, client)
            } case _ => error(invalid_request, s"mandatory: $grant_type, $refresh_token")
          }
        }
      }
    }
  }

  private def doProcess(
    refreshTokenRequest: RefreshTokenRequest,
    oauthClient: Oauth2Client)(implicit ctx: ExecutionContext): Future[Either[Err, AccessTokenResponse]] = {
    import oauth2.spec.AccessTokenErrors._

    refreshTokenRequest.getError(oauthClient) match {
      case Some(error) => Future.successful(Left(error))
      case None => store.getRefreshToken(refreshTokenRequest.refreshToken) flatMap {
        case None => error(invalid_grant, "invalid refresh token")
        case Some(refreshToken) if (refreshToken.isExpired) => error(invalid_grant, "refresh token expired")
        case Some(refreshToken) => {
          val accessToken = tokens.generateAccessToken(oauthClient, refreshToken.tokenScope, refreshToken.userId)
          store.storeTokens(AccessAndRefreshTokens(accessToken, None), oauthClient) map { stored =>
            val response = AccessTokenResponse(
              stored.accessToken.value,
              stored.refreshToken.map(_.value),
              TokenType.bearer,
              stored.accessToken.validity,
              refreshToken.tokenScope.mkString(ScopeSeparator))
            Right(response)
          }
        }
      }
    }
  }
}
