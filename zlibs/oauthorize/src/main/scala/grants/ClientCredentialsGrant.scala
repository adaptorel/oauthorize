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

  this: Oauth2Defaults with PasswordEncoder with Oauth2Store with AuthzCodeGenerator =>

  override def matches(r: OauthRequest) = {
    val accepts = r.path == accessTokenEndpoint &&
      r.method == "POST" &&
      r.param(Req.grant_type)
      .map(v => v == GrantTypes.client_credentials).getOrElse(false)
    accepts
  }

  def processClientCredentialsRequest(req: OauthRequest, clientAuth: Option[ClientAuthentication]): Future[Either[Err, AccessTokenResponse]] = Future {

    clientAuth match {
      case None => Left(err(unauthorized_client, "unauthorized client", StatusCodes.Unauthorized))
      case Some(basicAuth) => getClient(basicAuth.clientId) match {
        case None => Left(err(invalid_client, s"unregistered client ${basicAuth.clientId}", StatusCodes.Unauthorized))
        case Some(client) if (!passwordMatches(basicAuth.clientSecret, client.clientSecret)) => Left(err(invalid_client, "bad credentials", StatusCodes.Unauthorized))
        case Some(client) => {
          (req.param(grant_type)) match {
            case (Some(grantType)) => {
              val ccReq = ClientCredentialsRequest(client, req.param(scope))
              processClientCredentialsRequest(ccReq)
            } case _ => Left(err(invalid_request, s"mandatory: $grant_type"))
          }
        }
      }
    }
  }

  private def processClientCredentialsRequest(ccReq: ClientCredentialsRequest): Either[Err, AccessTokenResponse] = {
    import oauth2.spec.AccessTokenErrors._
    ccReq.getError() match {
      case Some(error) => Left(error)
      case None => {
        val accessToken = generateAccessToken(ccReq.client, ccReq.scope.map(_.split(ScopeSeparator).toSeq).getOrElse(Seq()))
        val refreshToken = if (ccReq.client.authorizedGrantTypes.contains(GrantTypes.refresh_token)) {
          Some(generateRefreshToken(ccReq.client))
        } else None
        val stored = storeTokens(AccessAndRefreshTokens(accessToken, refreshToken), ccReq.client)
        val response = AccessTokenResponse(stored.accessToken.value, stored.refreshToken.map(_.value), TokenType.bearer, stored.accessToken.validity, ccReq.scope.getOrElse(""))
        Right(response)
      }
    }
  }
}