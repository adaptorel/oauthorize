package oauthorize.grants

import scala.concurrent.{ ExecutionContext, Future }

import oauth2.spec.AuthzErrors.invalid_request
import oauth2.spec.Req._
import oauthorize.model._
import oauthorize.service._
import oauthorize.utils._

class ImplicitGrant(
  val config: Oauth2Config,
  val store: Oauth2Store) {

  def processImplicitRequest(
    req: OauthRequest,
    user: Oauth2User)(implicit ctx: ExecutionContext): Future[Either[Err, OauthResponse]] = {
    (req.param(client_id), req.param(response_type), req.param(redirect_uri), req.param(scope)) match {
      case (Some(clientId), Some(responseType), Some(redirectUri), Some(authzScope)) => {
        store.getClient(clientId) map {
          case None => Left(err(invalid_request, "unregistered client"))
          case Some(client) => {
            val authzRequest = AuthzRequest(
              None,
              clientId,
              responseType,
              redirectUri,
              authzScope.split(ScopeSeparator).toSeq,
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
      case _ => error(invalid_request, s"mandatory: $client_id, $response_type, $redirect_uri, $scope")
    }
  }
}