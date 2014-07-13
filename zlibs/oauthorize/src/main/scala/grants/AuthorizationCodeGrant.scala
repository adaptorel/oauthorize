package grants

import oauth2.spec.Req._
import oauth2.spec.AuthzErrors._
import oauth2.spec.model._
import oauth2.spec._
import scala.concurrent.Future
import oauthze.service._
import oauthze.utils._
import oauthze.model._

trait AuthorizationCode extends Dispatcher {

  this: OauthConfig with OauthClientStore with AuthzCodeGenerator with ExecutionContextProvider =>

  override def matches(r: OauthRequest) = {
    val res = r.path == authorizeEndpoint &&
      r.method == "GET" &&
      r.param(Req.response_type).map(_ == ResponseType.code).getOrElse(false)
    res
  }

  def processAuthorizeRequest(req: OauthRequest): Future[Either[Err, OauthResponse]] = Future {
    (req.param(client_id), req.param(response_type), req.param(redirect_uri), req.param(scope)) match {
      case (Some(clientId), Some(responseType), Some(redirectUri), Some(authzScope)) => {
        getClient(clientId) match {
          case None => Left(err(invalid_request, "unregistered client"))
          case Some(client) => {
            val authzRequest = AuthzRequest(clientId, responseType, redirectUri, authzScope.split(ScopeSeparator).toSeq, client.autoapprove, req.param(state))
            authzRequest.getError(client) match {
              case Some(err) => Left(err)
              case None => processAuthzRequest(authzRequest, client) match {
                case Left(err) => Left(err)
                case Right(authzCode) => Right(InitiateApproval(authzCode, authzRequest, client))
              }
            }
          }
        }
      }
      case _ => Left(err(invalid_request, s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }
  }
  
  private def processAuthzRequest(authzRequest: AuthzRequest, oauthClient: Oauth2Client): Either[Err, String] = {
    if (ResponseType.code != authzRequest.responseType ||
      !oauthClient.authorizedGrantTypes.contains(GrantTypes.authorization_code)) {
      Left(err(unsupported_response_type, "unsupported grant type"))
    } else {
      val authzCode = generateCode(authzRequest)
      Right(authzCode)
    }
  }
}