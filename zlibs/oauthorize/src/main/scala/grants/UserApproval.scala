package grants

import oauthze.model._
import oauth2.spec.Error._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthze.service._
import scala.concurrent.Future

object UserApproval {
  val Allow = "Allow"
  val Deny = "Deny"
  val AllowValue = "approve"
  val DenyValue = "deny"
}

trait UserApproval extends Dispatcher {
  this: OauthConfig with OauthClientStore =>

  override def matches(r: OauthRequest) = {
    val res = r.path == processApprovalEndpoint &&
      (r.method == "POST" || r.method == "GET")
    res
  }

  def processApprove(req: OauthRequest): OauthRedirect = {
    println(req.params);
    (for {
      authzCode <- req.param(code)
      authzRequest <- getAuthzRequest(authzCode)
      client <- getClient(authzRequest.clientId)
    } yield {
      val isApproved = req.param(UserApproval.Allow).map(_ == UserApproval.AllowValue).getOrElse(false)
      val redirectParams = if (isApproved) {
        val temp = Map(code -> authzCode)
        req.param(state).map(s => temp + (state -> s)).getOrElse(temp)
      } else {
        val temp = Map(error -> access_denied)
        req.param(state).map(s => temp + (state -> s)).getOrElse(temp)
      }
      OauthRedirect(s"${client.redirectUri}", redirectParams)
    }) getOrElse (throw new IllegalStateException("Process approval failure because of missing code, authzRequest, client or Allow parameter"))
  }
}