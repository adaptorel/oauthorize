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
  val tokens: TokenGenerator) extends Dispatcher {

  override def matches(r: OauthRequest) = {
    val res = r.path == config.accessTokenEndpoint &&
      r.method == "POST" &&
      r.param(Req.grant_type).exists(_ == GrantTypes.password)
    res
  }

  def processOwnerCredentialsRequest(req: OauthRequest, clientAuth: Option[ClientAuthentication])(implicit ctx: ExecutionContext): Future[Either[Err, AccessTokenResponse]] = Future {

    clientAuth match {
      case None => Left(err(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized))
      case Some(basicAuth) => oauthStore.getClient(basicAuth.clientId) match {
        case None => Left(err(invalid_client, "unregistered client", StatusCodes.Unauthorized))
        case Some(client) if (!clientSecretHasher.secretMatches(basicAuth.clientSecret, client.secretInfo)) => Left(err(invalid_client, "bad credentials", StatusCodes.Unauthorized))
        case Some(client) => {
          (req.param(grant_type), req.param(username), req.param(password), req.param(scope)) match {
            case (Some(grantType), Some(userName), Some(pwd), Some(authScope)) => {
              val rq = ResourceOwnerCredentialsRequest(grantType, userName, pwd, authScope.split(ScopeSeparator))
              processOwnerCredentialsRequest(rq, client)
            } case _ => Left(err(invalid_request, s"mandatory: $grant_type, $username, $password, $scope"))
          }
        }
      }
    }
  }

  private def processOwnerCredentialsRequest(rq: ResourceOwnerCredentialsRequest, oauthClient: Oauth2Client): Either[Err, AccessTokenResponse] = {
    import oauth2.spec.AccessTokenErrors._

    rq.getError(oauthClient) match {
      case Some(error) => Left(error)
      case None => {
        userStore.getUser(UserId(rq.username, None)) match {
          case None => Left(err(invalid_request, "no such user", 401))
          case Some(usr) if (usr.pwd.map(info => !userPasswordHasher.secretMatches(rq.password, info)).getOrElse(true)) =>
            Left(err(invalid_request, "bad user credentials", 401))
          case Some(usr) => {
            /*
             * TODO do we care about any previously stored data since he's started
             * the flow from the beginning, with the authorization code and everything?
             */
            val accessToken = tokens.generateAccessToken(oauthClient, rq.authScope, Some(usr.id))
            val refreshToken = if (oauthClient.authorizedGrantTypes.contains(GrantTypes.refresh_token)) {
              Some(tokens.generateRefreshToken(oauthClient, rq.authScope, Some(usr.id)))
            } else None
            val stored = oauthStore.storeTokens(AccessAndRefreshTokens(accessToken, refreshToken), oauthClient)
            val response = AccessTokenResponse(stored.accessToken.value, stored.refreshToken.map(_.value), TokenType.bearer, stored.accessToken.validity, rq.authScope.mkString(ScopeSeparator))
            Right(response)
          }
        }
      }
    }
  }
}