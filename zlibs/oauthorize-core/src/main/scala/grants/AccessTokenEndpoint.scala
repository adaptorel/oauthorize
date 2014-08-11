package oauthorize.grants

import oauthorize.utils._
import oauthorize.model._
import oauthorize.service._
import oauth2.spec.Req._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec._
import oauth2.spec.model._
import scala.concurrent.Future

trait AccessTokenEndpoint extends Dispatcher {

  this: Oauth2Defaults with ClientSecretHasher with Oauth2Store with AuthzCodeGenerator =>

  override def matches(r: OauthRequest) = {
    val res = r.path == accessTokenEndpoint &&
      r.method == "POST" &&
      r.param(Req.grant_type).exists(_ == GrantTypes.authorization_code)
    res
  }
    
  def processAccessTokenRequest(req: OauthRequest, clientAuth: Option[ClientAuthentication]): Future[Either[Err, AccessTokenResponse]] = Future {

    clientAuth match {
      case None => Left(err(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized))
      case Some(basicAuth) => getClient(basicAuth.clientId) match {
        case None => Left(err(invalid_client, "unregistered client", StatusCodes.Unauthorized))
        case Some(client) if (!clientSecretMatches(basicAuth.clientSecret, client.secretInfo)) => Left(err(invalid_client, "bad credentials", StatusCodes.Unauthorized))
        case Some(client) => {
          (req.param(grant_type), req.param(code), req.param(redirect_uri)) match {
            case (Some(grantType), Some(authzCode), Some(redirectUri)) => {
              val atRequest = AccessTokenRequest(grantType, authzCode, redirectUri, req.param(client_id))
              processAccessTokenRequest(atRequest, client)
            } case _ => Left(err(invalid_request, s"mandatory: $grant_type, $code, $redirect_uri"))
          }
        }
      }
    }
  }

  private def processAccessTokenRequest(accessTokenRequest: AccessTokenRequest, oauthClient: Oauth2Client): Either[Err, AccessTokenResponse] = {
    import oauth2.spec.AccessTokenErrors._

    getAuthzRequest(accessTokenRequest.authzCode) match {
      case None => Left(err(invalid_request, "invalid authorization code"))
      case Some(authzRequest) if (authzRequest.isExpired) => Left(err(invalid_request, "expired authorization code"))
      case Some(authzRequest) => {
        markForRemoval(authzRequest, Option(accessTokenRequest.authzCode))
        accessTokenRequest.getError(authzRequest, oauthClient) match {
          case Some(error) => Left(error)
          case None => {
            /*
             * TODO do we care about any previously stored data since he's started
             * the flow from the beginning, with the authorization code and everything?
             */
            val accessToken = generateAccessToken(oauthClient, authzRequest.authScope, authzRequest.user.map(_.id))
            val refreshToken = if (oauthClient.authorizedGrantTypes.contains(GrantTypes.refresh_token)) {
              Some(generateRefreshToken(oauthClient, authzRequest.authScope, authzRequest.user.map(_.id)))
            } else None
            val stored = storeTokens(AccessAndRefreshTokens(accessToken, refreshToken), oauthClient)
            val response = AccessTokenResponse(stored.accessToken.value, stored.refreshToken.map(_.value), TokenType.bearer, stored.accessToken.validity, authzRequest.authScope.mkString(ScopeSeparator))
            Right(response)
          }
        }
      }
    }
  }
}
