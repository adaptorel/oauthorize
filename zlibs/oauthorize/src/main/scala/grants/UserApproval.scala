package oauthorize.grants

import oauthorize.model._
import oauth2.spec.Error._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthorize.service._
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
  this: OauthConfig with Oauth2Store =>

  def unmarshal(jsonString: String): Option[AuthzRequest]

  override def matches(r: OauthRequest) = {
    val res = r.path == processApprovalEndpoint &&
      (r.method == "POST" || r.method == "GET")
    res
  }

  def processApprove(req: OauthRequest, u: Oauth2User): OauthRedirect = {
    println(" -- processing approval: " + req)
    (for {
      authzCode <- req.param(code)
      authzRequestJsonString <- req.param(UserApproval.AuthzRequestKey)
      authzRequest <- unmarshal(authzRequestJsonString)
      client <- getClient(authzRequest.clientId)
    } yield {
      val redirectParams = if (isApproved(req)) {
        storeAuthzRequest(authzCode, authzRequest.copy(user = Option(u)))
        val temp = Map(code -> authzCode)
        req.param(state).map(s => temp + (state -> s)).getOrElse(temp)
      } else {
        val temp = Map(error -> access_denied)
        req.param(state).map(s => temp + (state -> s)).getOrElse(temp)
      }
      OauthRedirect(s"${client.redirectUri}", redirectParams)
    }) getOrElse (throw new IllegalStateException("Process approval failure because of missing code, authzRequest, client or Allow parameter"))
  }

  private def isApproved(req: OauthRequest) = {
    req.param(UserApproval.Allow).map(_ == UserApproval.AllowValue).getOrElse(false) ||
      req.param(UserApproval.AutoApproveKey).map(_ == "true").getOrElse(false)
  }
}