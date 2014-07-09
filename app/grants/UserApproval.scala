package grants

import oauthze.model._
import oauth2.spec.Error._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthze.service._
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import scala.concurrent.Future
import oauth2.spec.Req

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
      r.method == "POST"
    res
  }

  private def approved(authzCode: String, maybeState: Option[String], client: Oauth2Client) = {
    val temp = Map(code -> authzCode)
    val params = maybeState.map(s => temp + (state -> s)).getOrElse(temp)
    OauthRedirect(s"${client.redirectUri}", params)
  }

  def processApprove(req: OauthRequest): OauthRedirect = {
    (for {
      authzCode <- req.param(code)
      authzRequest <- getAuthzRequest(authzCode)
      client <- getClient(authzRequest.clientId)
      isApproved <- req.param(UserApproval.Allow).map(_ == UserApproval.AllowValue)
    } yield {
      if (isApproved) {
        approved(authzCode, req.param(state), client)
      } else {
        val temp = Map(error -> access_denied)
        val params = req.param(state).map(s => temp + (state -> s)).getOrElse(temp)
        OauthRedirect(s"${client.redirectUri}", params)
      }
    }) getOrElse (throw new IllegalStateException("Process approval failure because of missing code, authzRequest, client or Allow parameter"))
  }
}