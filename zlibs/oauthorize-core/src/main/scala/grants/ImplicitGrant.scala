package oauthorize.grants

import oauth2.spec.Req._
import oauth2.spec.AuthzErrors._
import oauth2.spec.model._
import oauth2.spec._
import scala.concurrent.Future
import oauthorize.service._
import oauthorize.utils._
import oauthorize.model._
import oauthorize.model.OauthRedirect
import scala.collection.immutable.ListMap

class ImplicitGrant(
  val config: Oauth2Config,
  val store: Oauth2Store) {

  def processImplicitRequest(req: OauthRequest, user: Oauth2User): Either[Err, OauthResponse] = {
    (req.param(client_id), req.param(response_type), req.param(redirect_uri), req.param(scope)) match {
      case (Some(clientId), Some(responseType), Some(redirectUri), Some(authzScope)) => {
        store.getClient(clientId) match {
          case None => Left(err(invalid_request, "unregistered client"))
          case Some(client) => {
            val authzRequest = AuthzRequest(None, clientId, responseType, redirectUri, authzScope.split(ScopeSeparator).toSeq,
              client.autoapprove, config.authzCodeValiditySeconds, System.currentTimeMillis, req.param(state))
            authzRequest.getError(client) match {
              case Some(err) => Left(err)
              case None => Right(InitiateAuthzApproval(authzRequest, client))
            }
          }
        }
      }
      case _ => Left(err(invalid_request, s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }
  }
}

