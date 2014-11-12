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

class ResourceOwnerCredentialsGrant(
  val config: Oauth2Config,
  val oauthStore: Oauth2Store,
  val clientSecretHasher: ClientSecretHasher,
  val userStore: UserStore,
  val userPasswordHasher: UserPasswordHasher,
  val tokens: TokenGenerator) {

  def processOwnerCredentialsRequest(
    req: OauthRequest,
    clientAuth: Option[ClientAuthentication])(implicit ctx: ExecutionContext): Future[Either[Err, AccessTokenResponse]] = {

    clientAuth match {
      case None => error(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized)
      case Some(basicAuth) => oauthStore.getClient(basicAuth.clientId) flatMap {
        case None => error(invalid_client, "unregistered client", StatusCodes.Unauthorized)
        case Some(client) if (!clientSecretHasher.secretMatches(basicAuth.clientSecret, client.secretInfo)) =>
          error(invalid_client, "bad credentials", StatusCodes.Unauthorized)
        case Some(client) =>
          (req.param(grant_type), req.param(username), req.param(password), req.param(scope)) match {
            case (Some(grantType), Some(userName), Some(pwd), Some(authScope)) => {
              val rq = ResourceOwnerCredentialsRequest(grantType, userName, pwd, authScope.split(ScopeSeparator))
              doProcess(rq, client)
            } case _ => error(invalid_request, s"mandatory: $grant_type, $username, $password, $scope")
          }
      }
    }
  }

  private def doProcess(
    rq: ResourceOwnerCredentialsRequest,
    oauthClient: Oauth2Client)(implicit ctx: ExecutionContext): Future[Either[Err, AccessTokenResponse]] = {
    import oauth2.spec.AccessTokenErrors._

    rq.getError(oauthClient) match {
      case Some(error) => Future.successful(Left(error))
      case None => {
        userStore.getUser(UserId(rq.username, None)) match {
          case None => error(invalid_request, "no such user", 401)
          case Some(usr) if (usr.pwd.map(info => !userPasswordHasher.secretMatches(rq.password, info)).getOrElse(true)) =>
            error(invalid_request, "bad user credentials", 401)
          case Some(usr) => {
            val accessToken = tokens.generateAccessToken(oauthClient, rq.authScope, Some(usr.id))
            val refreshToken = if (oauthClient.authorizedGrantTypes.contains(GrantTypes.refresh_token)) {
              Some(tokens.generateRefreshToken(oauthClient, rq.authScope, Some(usr.id)))
            } else None
            oauthStore.storeTokens(AccessAndRefreshTokens(accessToken, refreshToken), oauthClient) map { stored =>
              val response = AccessTokenResponse(
                stored.accessToken.value,
                stored.refreshToken.map(_.value),
                TokenType.bearer,
                stored.accessToken.validity,
                rq.authScope.mkString(ScopeSeparator))
              Right(response)
            }
          }
        }
      }
    }
  }
}