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

trait ImplicitGrant extends Dispatcher {

  this: Oauth2Defaults with Oauth2Store with AuthzCodeGenerator =>

  override def matches(r: OauthRequest) = {
    val res =
      r.path == authorizeEndpoint &&
        r.method == "GET" &&
        r.param(Req.response_type).map(_ == ResponseType.token).getOrElse(false)
    res
  }

  def processImplicitRequest(req: OauthRequest): Future[Either[Err, OauthResponse]] = Future {
    (req.param(client_id), req.param(response_type), req.param(redirect_uri), req.param(scope)) match {
      case (Some(clientId), Some(responseType), Some(redirectUri), Some(authzScope)) => {
        getClient(clientId) match {
          case None => Left(err(invalid_request, "unregistered client"))
          case Some(client) => {
            val authzRequest = AuthzRequest(clientId, responseType, redirectUri, authzScope.split(ScopeSeparator).toSeq, client.autoapprove, req.param(state))
            authzRequest.getError(client) match {
              case Some(err) => Left(err)
              case None => processImplicitRequest(authzRequest, client) match {
                case Left(err) => Left(err)
                case Right(resp) => Right(renderImplicitResponse(resp, client))
              }
            }
          }
        }
      }
      case _ => Left(err(invalid_request, s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }
  }

  private def renderImplicitResponse(implicitResponse: ImplicitResponse, client: Oauth2Client) = {
    import oauth2.spec.AccessTokenResponseParams._
    val params = ListMap[String, Any]() +
      (access_token -> implicitResponse.access_token) +
      (token_type -> TokenType.bearer) +
      (expires_in -> implicitResponse.expires_in) +
      (scope -> implicitResponse.scope) +
      (state -> implicitResponse.state)
    OauthRedirect(encodedQueryString(client.redirectUri, params, "#"), Map())
  }

  import oauth2.spec.TokenType.bearer
  private def processImplicitRequest(authzRequest: AuthzRequest, oauthClient: Oauth2Client): Either[Err, ImplicitResponse] = {
    if (ResponseType.token != authzRequest.responseType || !oauthClient.authorizedGrantTypes.contains(GrantTypes.implic1t)) {
      Left(err(unsupported_response_type, "unsupported grant type"))
    } else {
      val token = generateAccessToken(oauthClient, authzRequest.authScope)
      val stored = storeTokens(AccessAndRefreshTokens(token), oauthClient)
      val expiresIn = stored.accessToken.validity
      Right(ImplicitResponse(stored.accessToken.value, bearer, expiresIn, authzRequest.authScope.mkString(ScopeSeparator), authzRequest.state))
    }
  }
}

