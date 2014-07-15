package oauthorize.grants

import oauth2.spec.{ResponseType, TokenType}
import oauth2.spec.TokenType._
import oauth2.spec.model.ImplicitResponse
import oauth2.spec.Error._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthorize.model._
import oauthorize.service._
import oauthorize.utils._
import scala.collection.immutable.ListMap
import scala.concurrent.Future

object UserApproval {
  val Allow = "Allow"
  val Deny = "Deny"
  val AllowValue = "approve"
  val DenyValue = "deny"
  val AuthzRequestKey = "_authz"
  val AutoApproveKey = "_auto"
}

trait UserApproval extends Dispatcher {
  this: Oauth2Defaults with Oauth2Store with AuthzCodeGenerator =>

  def unmarshal(authzRequestJsonString: String): Option[AuthzRequest]

  override def matches(r: OauthRequest) = {
    val res = r.path == userApprovalEndpoint &&
      (r.method == "POST" || r.method == "GET")
    res
  }

  def processApprove(req: OauthRequest, u: Oauth2User): OauthRedirect = {
    (for {
      authzRequestJsonString <- req.param(UserApproval.AuthzRequestKey)
      authzRequest <- unmarshal(authzRequestJsonString)
      client <- getClient(authzRequest.clientId)
    } yield {
      if (isApproved(req)) {
        if (ResponseType.token == authzRequest.responseType) {
          renderImplicitResponse(req, client, authzRequest, u)
        } else {
          renderAuthzResponse(authzRequest, client, req, u)
        }
      } else {
        renderAccessDenied(req, client)
      }
    }) getOrElse (throw new IllegalStateException("Process approval failure because of missing code, authzRequest, client or Allow parameter"))
  }

  private def isApproved(req: OauthRequest) = {
    req.param(UserApproval.Allow).map(_ == UserApproval.AllowValue).getOrElse(false) ||
      req.param(UserApproval.AutoApproveKey).map(_ == "true").getOrElse(false)
  }

  private def renderImplicitResponse(req: OauthRequest, oauthClient: Oauth2Client, authzRequest: AuthzRequest, user: Oauth2User) = {
    import oauth2.spec.AccessTokenResponseParams._

    val token = generateAccessToken(oauthClient, authzRequest.authScope, Option(user.id))
    val stored = storeTokens(AccessAndRefreshTokens(token), oauthClient)
    val expiresIn = stored.accessToken.validity
    val implicitResponse = ImplicitResponse(stored.accessToken.value, bearer, expiresIn, authzRequest.authScope.mkString(ScopeSeparator), authzRequest.state)
    val params = ListMap[String, Any]() +
      (access_token -> implicitResponse.access_token) +
      (token_type -> TokenType.bearer) +
      (expires_in -> implicitResponse.expires_in) +
      (scope -> implicitResponse.scope) +
      (state -> implicitResponse.state)
    OauthRedirect(encodedQueryString(oauthClient.redirectUri, params, "#"), Map())
  }

  private def renderAuthzResponse(authzRequest: AuthzRequest, client: Oauth2Client, req: OauthRequest, u: Oauth2User) = {
    val authzCode = generateCode(authzRequest)
    storeAuthzRequest(authzCode, authzRequest.copy(user = Option(u)))
    val redirectParams = Map(code -> authzCode)
    req.param(state).map(s => redirectParams + (state -> s)).getOrElse(redirectParams)
    OauthRedirect(s"${client.redirectUri}", redirectParams)
  }

  private def renderAccessDenied(req: OauthRequest, client: Oauth2Client) = {
    val redirectParams = Map(error -> access_denied)
    req.param(state).map(s => redirectParams + (state -> s)).getOrElse(redirectParams)
    OauthRedirect(s"${client.redirectUri}", redirectParams)
  }
}