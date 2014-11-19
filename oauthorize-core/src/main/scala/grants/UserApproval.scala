package oauthorize.grants

import oauth2.spec.{ ResponseType, TokenType }
import oauth2.spec.Error
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthorize.model._
import oauthorize.service._
import oauthorize.utils._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext

object UserApproval {
  val Allow = "Allow"
  val Deny = "Deny"
  val AllowValue = "approve"
  val DenyValue = "deny"
  val AuthzRequestKey = "_authz"
  val AutoApproveKey = "_auto"
}

trait AuthzDeserializer {
  def fromJson(authzRequestJsonString: String): Option[AuthzRequest]
}

class UserApproval(
  val config: Oauth2Config,
  val store: Oauth2Store,
  val tokens: TokenGenerator,
  val deserializer: AuthzDeserializer) {

  def processApprove(
    req: OauthRequest,
    u: Oauth2User)(implicit ctx: ExecutionContext, tenant: Tenant): Future[OauthRedirect] = {

    (for {
      authzRequestJsonString <- req.param(UserApproval.AuthzRequestKey)
      authzReq <- deserializer.fromJson(authzRequestJsonString)
    } yield {
      store.getClient(authzReq.clientId) flatMap {
        case None => throw new IllegalStateException("Process approval failure because of inexistsent Oauth2 client")
        case Some(client) =>
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
      }
    }).getOrElse(Future.successful(
      throw new RuntimeException("Something bad happened when processing user approval, all params were ours, we can't fail!")))
  }

  private def isApproved(req: OauthRequest, client: Oauth2Client) = {
    if (req.param(UserApproval.AutoApproveKey).exists(_ == "true") && !client.autoapprove) {
      throw new IllegalStateException("Most probably a hand crafted autoapprove URL. Autoapprove req param was true but the client setting is false.")
    }
    val autoApprove = (req.param(UserApproval.AutoApproveKey).exists(_ == "true") && client.autoapprove)
    req.param(UserApproval.Allow).exists(_ == UserApproval.AllowValue) || autoApprove
  }

  import scala.collection.immutable.ListMap

  private def renderImplicitResponse(
    req: OauthRequest,
    oauthClient: Oauth2Client,
    authzRequest: AuthzRequest,
    user: Oauth2User)(implicit ctx: ExecutionContext, tenant: Tenant) = {
    import oauth2.spec.AccessTokenResponseParams._

    // authz req not stored thus we have no code for implicit grant
    store.markForRemoval(authzRequest, None) flatMap { empty =>
      val token = tokens.generateAccessToken(oauthClient, authzRequest.authScope, Option(user.id))
      store.storeTokens(AccessAndRefreshTokens(token), oauthClient) map { stored =>
        val tmp = ListMap[String, String]() +
          (access_token -> stored.accessToken.value) +
          (token_type -> TokenType.bearer) +
          (expires_in -> stored.accessToken.validity.toString) +
          (scope -> authzRequest.authScope.mkString(ScopeSeparator))
        val params = authzRequest.state.map(st => tmp + (state -> st)).getOrElse(tmp)
        OauthRedirect(oauthClient.redirectUri, params, true)
      }
    }
  }

  private def renderAuthzResponse(
    authzRequest: AuthzRequest,
    client: Oauth2Client,
    req: OauthRequest,
    u: Oauth2User)(implicit ctx: ExecutionContext, tenant: Tenant) = {

    val authzCode = tokens.generateCode(authzRequest)
    store.storeAuthzRequest(authzCode, authzRequest.copy(user = Option(u), code = Option(authzCode))) map { stored =>
      val tmp = Map(code -> authzCode)
      val params = authzRequest.state.map(s => tmp + (state -> s)).getOrElse(tmp)
      OauthRedirect(s"${client.redirectUri}", params)
    }
  }

  private def renderAccessDenied(
    req: OauthRequest,
    client: Oauth2Client)(implicit ctx: ExecutionContext) = {
    val redirectParams = Map(Error.error -> access_denied)
    req.param(state).map(s => redirectParams + (state -> s)).getOrElse(redirectParams)
    Future.successful(OauthRedirect(s"${client.redirectUri}", redirectParams))
  }
}