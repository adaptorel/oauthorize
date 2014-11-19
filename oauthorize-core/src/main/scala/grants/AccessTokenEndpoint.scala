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

class AccessTokenEndpoint(
  val config: Oauth2Config,
  val store: Oauth2Store,
  val hasher: ClientSecretHasher,
  val tokens: TokenGenerator) {

  def processAccessTokenRequest(
    req: OauthRequest,
    clientAuth: Option[ClientAuthentication])(implicit ctx: ExecutionContext): Future[Either[Err, AccessTokenResponse]] = {
    
    clientAuth match {
      case None => error(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized)
      case Some(basicAuth) => store.getClient(basicAuth.clientId) flatMap {
        case None => error(invalid_client, "unregistered client", StatusCodes.Unauthorized)
        case Some(client) if (!hasher.secretMatches(basicAuth.clientSecret, client.secretInfo)) =>
          error(invalid_client, "bad credentials", StatusCodes.Unauthorized)
        case Some(client) => {
          (req.param(grant_type), req.param(code), req.param(redirect_uri)) match {
            case (Some(grantType), Some(authzCode), Some(redirectUri)) => {
              val atRequest = AccessTokenRequest(grantType, authzCode, redirectUri, req.param(client_id))
              doProcess(atRequest, client)
            } case _ => error(invalid_request, s"mandatory: $grant_type, $code, $redirect_uri")
          }
        }
      }
    }
  }

  private def doProcess(
    accessTokenRequest: AccessTokenRequest,
    oauthClient: Oauth2Client)(implicit ctx: ExecutionContext): Future[Either[Err, AccessTokenResponse]] = {
    import oauth2.spec.AccessTokenErrors._

    store.getAuthzRequest(accessTokenRequest.authzCode) flatMap {
      case None => error(invalid_request, "invalid authorization code")
      case Some(authzRequest) if (authzRequest.isExpired) =>
        error(invalid_request, "expired authorization code")
      case Some(authzRequest) =>
        store.markForRemoval(authzRequest, Option(accessTokenRequest.authzCode)) flatMap { empty =>
          accessTokenRequest.getError(authzRequest, oauthClient) match {
            case Some(error) => Future.successful(Left(error))
            case None =>
              val accessToken = tokens.generateAccessToken(oauthClient, authzRequest.authScope, authzRequest.user.map(_.id))
              val refreshToken = if (oauthClient.authorizedGrantTypes.contains(GrantTypes.refresh_token)) {
                Some(tokens.generateRefreshToken(oauthClient, authzRequest.authScope, authzRequest.user.map(_.id)))
              } else None
              store.storeTokens(AccessAndRefreshTokens(accessToken, refreshToken), oauthClient) map { stored =>
                val response = AccessTokenResponse(
                  stored.accessToken.value,
                  stored.refreshToken.map(_.value),
                  TokenType.bearer,
                  stored.accessToken.validity,
                  authzRequest.authScope.mkString(ScopeSeparator))
                Right(response)
              }
          }
        }
    }
  }
}
