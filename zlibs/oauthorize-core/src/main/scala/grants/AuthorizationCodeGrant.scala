package oauthorize.grants

import oauth2.spec.Req._
import oauth2.spec.AuthzErrors._
import oauth2.spec.model._
import oauth2.spec._
import scala.concurrent.Future
import oauthorize.service._
import oauthorize.utils._
import oauthorize.model._

trait AuthorizationCode extends Dispatcher {

  this: Oauth2Defaults with Oauth2Store with TokenGenerator =>

  override def matches(r: OauthRequest) = {
    val res = r.path == authorizeEndpoint &&
      r.method == "GET" &&
      r.param(Req.response_type).exists(_ == ResponseType.code)
    res
  }

  def processAuthorizeRequest(req: OauthRequest): Future[Either[Err, OauthResponse]] = Future {
    (req.param(client_id), req.param(response_type), req.param(redirect_uri)) match {
      case (Some(clientId), Some(responseType), Some(redirectUri)) => {
        getClient(clientId) match {
          case None => Left(err(invalid_request, "unregistered client"))
          case Some(client) => {
            val scopes = req.param(scope).map(_.split(ScopeSeparator).toSeq).getOrElse(Seq())
            val authzRequest = AuthzRequest(None, clientId, responseType, redirectUri, scopes, client.autoapprove, authzCodeValiditySeconds, System.currentTimeMillis, req.param(state))
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