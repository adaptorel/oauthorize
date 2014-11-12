package oauthorize.grants

import oauth2.spec.{ ResponseType, TokenType }
import oauth2.spec.Error._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthorize.model._
import oauthorize.service._
import oauthorize.utils._
import scala.concurrent.Future

object UserApproval {
  val Allow = "Allow"
  val Deny = "Deny"
  val AllowValue = "approve"
  val DenyValue = "deny"
  val AuthzRequestKey = "_authz"
  val AutoApproveKey = "_auto"
}

abstract class UserApproval(
  val config: Oauth2Config,
  val store: Oauth2Store,
  val tokens: TokenGenerator) {

  def unmarshal(authzRequestJsonString: String): Option[AuthzRequest]

  def processApprove(req: OauthRequest, u: Oauth2User): OauthRedirect = {
    (for {
      authzRequestJsonString <- req.param(UserApproval.AuthzRequestKey)
      authzReq <- unmarshal(authzRequestJsonString)
      client <- store.getClient(authzReq.clientId)
    } yield {
      if (isApproved(req, client)) {
        //we consider created 
        val authzRequest = authzReq.copy(created = System.currentTimeMillis)
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

  private def isApproved(req: OauthRequest, client: Oauth2Client) = {
    if (req.param(UserApproval.AutoApproveKey).exists(_ == "true") && !client.autoapprove) {
      throw new IllegalStateException("Most probably a hand crafted autoapprove URL. Autoapprove req param was true but the client setting is false.")
    }
    val autoApprove = (req.param(UserApproval.AutoApproveKey).exists(_ == "true") && client.autoapprove)
    req.param(UserApproval.Allow).exists(_ == UserApproval.AllowValue) || autoApprove
  }

  import scala.collection.immutable.ListMap
  private def renderImplicitResponse(req: OauthRequest, oauthClient: Oauth2Client, authzRequest: AuthzRequest, user: Oauth2User) = {
    import oauth2.spec.AccessTokenResponseParams._
    store.markForRemoval(authzRequest, None)// authz req not stored thus we have no code for implicit grant
    val token = tokens.generateAccessToken(oauthClient, authzRequest.authScope, Option(user.id))
    val stored = store.storeTokens(AccessAndRefreshTokens(token), oauthClient)
    val tmp = ListMap[String, String]() +
      (access_token -> stored.accessToken.value) +
      (token_type -> TokenType.bearer) +
      (expires_in -> stored.accessToken.validity.toString) +
      (scope -> authzRequest.authScope.mkString(ScopeSeparator))
    val params = authzRequest.state.map(st => tmp + (state -> st)).getOrElse(tmp)
    OauthRedirect(oauthClient.redirectUri, params, true)
  }

  private def renderAuthzResponse(authzRequest: AuthzRequest, client: Oauth2Client, req: OauthRequest, u: Oauth2User) = {
    val authzCode = tokens.generateCode(authzRequest)
    store.storeAuthzRequest(authzCode, authzRequest.copy(user = Option(u), code = Option(authzCode)))
    val tmp = Map(code -> authzCode)
    val params = authzRequest.state.map(s => tmp + (state -> s)).getOrElse(tmp)
    OauthRedirect(s"${client.redirectUri}", params)
  }

  private def renderAccessDenied(req: OauthRequest, client: Oauth2Client) = {
    val redirectParams = Map(error -> access_denied)
    req.param(state).map(s => redirectParams + (state -> s)).getOrElse(redirectParams)
    OauthRedirect(s"${client.redirectUri}", redirectParams)
  }
}