package oauthorize.grants

import oauthorize.utils._
import oauthorize.model._
import oauthorize.service._
import oauth2.spec.Req._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec._
import oauth2.spec.model._
import scala.concurrent.Future

trait ClientCredentialsGrant extends Dispatcher {

  this: Oauth2Defaults with ClientSecretHasher with Oauth2Store with AuthzCodeGenerator =>

  override def matches(r: OauthRequest) = {
    val accepts = r.path == accessTokenEndpoint &&
      r.method == "POST" &&
      r.param(Req.grant_type).exists(_ == GrantTypes.client_credentials)
    accepts
  }

  def processClientCredentialsRequest(req: OauthRequest, clientAuth: Option[ClientAuthentication])(implicit tenant: Tenant): Future[Either[Err, AccessTokenResponse]] = Future {

    clientAuth match {
      case None => Left(err(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized))
      case Some(basicAuth) => getClient(basicAuth.clientId) match {
        case None => Left(err(invalid_client, s"unregistered client", StatusCodes.Unauthorized))
        case Some(client) if (!clientSecretMatches(basicAuth.clientSecret, client.secretInfo)) => Left(err(invalid_client, "bad credentials", StatusCodes.Unauthorized))
        case Some(client) => {
          (req.param(grant_type)) match {
            case (Some(grantType)) => {
              val ccReq = ClientCredentialsRequest(grantType, client, req.param(scope))
              processClientCredentialsRequest(ccReq, client)
            } case _ => Left(err(invalid_request, s"mandatory: $grant_type"))
          }
        }
      }
    }
  }

  private def processClientCredentialsRequest(ccReq: ClientCredentialsRequest, client: Oauth2Client)(implicit tenant: Tenant): Either[Err, AccessTokenResponse] = {
    import oauth2.spec.AccessTokenErrors._
    ccReq.getError(client) match {
      case Some(error) => Left(error)
      case None => {
        val scopes = ccReq.authScope.map(_.split(ScopeSeparator).toSeq).getOrElse(Seq())
        val accessToken = generateAccessToken(ccReq.client, scopes, None) //no user for c_c
        val refreshToken = if (ccReq.client.authorizedGrantTypes.contains(GrantTypes.refresh_token)) {
          Some(generateRefreshToken(ccReq.client, scopes, None))
        } else None
        val stored = storeTokens(AccessAndRefreshTokens(accessToken, refreshToken), ccReq.client)
        val response = AccessTokenResponse(
          stored.accessToken.value,
          stored.refreshToken.map(_.value),
          TokenType.bearer,
          stored.accessToken.validity,
          scopes.mkString(ScopeSeparator))
        Right(response)
      }
    }
  }
}