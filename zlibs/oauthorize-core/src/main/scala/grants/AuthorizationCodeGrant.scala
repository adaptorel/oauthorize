package oauthorize.grants

import oauth2.spec.Req._
import oauth2.spec.AuthzErrors._
import oauth2.spec.model._
import oauth2.spec._
import oauthorize.service._
import oauthorize.utils._
import oauthorize.model._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext

class AuthorizationCode(
  val config: Oauth2Config,
  val store: Oauth2Store) {

  def processAuthorizeRequest(req: OauthRequest)(implicit ctx: ExecutionContext, tenant: Tenant): Future[Either[Err, OauthResponse]] = {
    (req.param(client_id), req.param(response_type), req.param(redirect_uri)) match {
      case (Some(clientId), Some(responseType), Some(redirectUri)) => {
        store.getClient(clientId) map {
          case None => Left(err(invalid_request, "unregistered client"))
          case Some(client) => {
            val scopes = req.param(scope).map(_.split(ScopeSeparator).toSeq).getOrElse(Seq())
            val authzRequest = AuthzRequest(
              None,
              clientId,
              responseType,
              redirectUri,
              scopes,
              client.autoapprove,
              config.authzCodeValiditySeconds,
              System.currentTimeMillis,
              req.param(state))
            authzRequest.getError(client) match {
              case Some(err) => Left(err)
              case None => Right(InitiateAuthzApproval(authzRequest, client))
            }
          }
        }
      }
      case _ => Future.successful(Left(err(invalid_request, s"mandatory: $client_id, $response_type, $redirect_uri, $scope")))
    }
  }
}