package oauthorize.playapp.grants

import play.api.mvc._
import play.api.mvc.Results._
import play.api.libs.json.Json
import oauthorize.model._
import oauthorize.service._
import oauthorize.grants._
import json._
import oauthorize.utils.BasicAuthentication
import scala.concurrent.Future
import play.filters.csrf._
import play.filters.csrf.CSRFAddToken
import play.api.libs.Crypto

trait Oauth2RequestValidatorPlay extends Oauth2BodyReaderFilter with Oauth2RequestValidator with RenderingUtils {
  this: Oauth2Defaults with Oauth2Store with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    logInfo(s"proceed with global validation at: $a")
    getErrors(a).map(maybeErr => maybeErr.map(renderErrorAsResult(_)))
  }
}

trait AccessTokenEndpointPlay extends Oauth2BodyReaderFilter with AccessTokenEndpoint with RenderingUtils {
  this: Oauth2Defaults with ClientSecretHasher with Oauth2Store with AuthzCodeGenerator =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processAccessTokenRequest(oauthRequest, BasicAuthentication(oauthRequest)).map(_.fold(err => err, correct => correct)))
  }
}

trait RefreshTokenEndpointPlay extends Oauth2BodyReaderFilter with RefreshTokenEndpoint with RenderingUtils {
  this: Oauth2Defaults with ClientSecretHasher with Oauth2Store with AuthzCodeGenerator =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processRefreshTokenRequest(oauthRequest, BasicAuthentication(oauthRequest)).map(_.fold(err => err, correct => correct)))
  }
}

trait ClientCredentialsGrantPlay extends Oauth2BodyReaderFilter with ClientCredentialsGrant with RenderingUtils {
  this: Oauth2Defaults with ClientSecretHasher with Oauth2Store with AuthzCodeGenerator =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processClientCredentialsRequest(oauthRequest, BasicAuthentication(oauthRequest)).map(_.fold(err => err, correct => correct)))
  }
}

object WithCsrf {
  def apply(req: RequestHeader, response: OauthResponse, cfg: Oauth2Config): OauthResponse = {
    response match {
      case a: InitiateAuthzApproval if (cfg.csrfEnabled && a.client.autoapprove) =>
        a.copy(csrfToken = CSRF.getToken(req).map(_.value))
      case any => any
    }
  }
}

trait AuthorizationCodePlay extends Oauth2BodyReaderFilter with AuthorizationCode with RenderingUtils {
  this: Oauth2Defaults with Oauth2Store with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    Option(processAuthorizeRequest(a).map(_.fold(err => err, good => WithCsrf(req, good, this))))
  }
}

trait ResourceOwnerCredentialsGrantPlay extends Oauth2BodyReaderFilter with ResourceOwnerCredentialsGrant with RenderingUtils {
  this: Oauth2Defaults with ClientSecretHasher with Oauth2Store with UserStore with UserPasswordHasher with AuthzCodeGenerator =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processOwnerCredentialsRequest(oauthRequest, BasicAuthentication(oauthRequest)).map(_.fold(err => err, correct => correct)))
  }
}

trait ImplicitGrantPlay extends Oauth2BodyReaderFilter with ImplicitGrant with RenderingUtils with securesocial.core.SecureSocial {
  this: Oauth2Defaults with Oauth2Store with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    def process(u: Oauth2User): SimpleResult = processImplicitRequest(a, u).fold(err => err, good => WithCsrf(req, good, this))
    Some(secureInvocation(process, req))
  }

  private def secureInvocation(block: (Oauth2User) => Result, req: RequestHeader) = {
    (SecuredAction { implicit r => block(UserExtractor(r)) })(req).run
  }

}

trait UserApprovalPlay extends Oauth2BodyReaderFilter with UserApproval with RenderingUtils with securesocial.core.SecureSocial {
  this: Oauth2Defaults with Oauth2Store with AuthzCodeGenerator =>

  import oauth2.spec.Req._
  import oauthorize.utils._
  import oauth2.spec.AuthzErrors._
  import scala.concurrent.Await
  import scala.concurrent.duration._

  override def unmarshal(authzRequestJsonString: String) = Json.parse(authzRequestJsonString).asOpt[AuthzRequest]

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    logInfo(s"processing user approval: $a");
    def lazyResult(u: Oauth2User) =
      if ("POST" == a.method || a.param(UserApproval.AutoApproveKey).exists(_ == "true"))
        lazyProcessApprove(a, u, req)
      else displayUserApprovalPage(a, req)
    Some(secureInvocation(lazyResult, req))
  }

  private def lazyProcessApprove(a: OauthRequest, u: Oauth2User, req: RequestHeader): SimpleResult = {
    CsrfCheck(req, a, this) {
      processApprove(a, u)
    }.withSession(req.session - CSRF.TokenName)
  }

  def buildUserApprovalPage(authzReq: AuthzRequest, authzRequestJsonString: String, client: Oauth2Client, req: RequestHeader): SimpleResult = {
    Ok(views.html.oauthz.user_approval(authzReq, authzRequestJsonString, client, req))
  }

  private def displayUserApprovalPage(a: OauthRequest, req: RequestHeader): SimpleResult = {
    implicit val request = req
    (for {
      authzRequestJsonString <- a.param(UserApproval.AuthzRequestKey)
      authzReq <- unmarshal(authzRequestJsonString)
      client <- getClient(authzReq.clientId)
    } yield {
      buildUserApprovalPage(authzReq, authzRequestJsonString, client, req)
    }) getOrElse ({
      logError("Fatal error when initiating user approval after user authentication! The authorization code, authorization request or the client weren't found. Shouldn't have got here EVER, we're controlling the whole flow!")
      err(server_error, 500)
    })
  }

  private def secureInvocation(block: (Oauth2User) => Result, req: RequestHeader) = {
    (SecuredAction { implicit r => block(UserExtractor(r)) })(req).run
  }

  object CsrfCheck {
    def apply(req: RequestHeader, a: OauthRequest, cfg: Oauth2Config)(block: => OauthResponse): OauthResponse = {
      val isCsrfCheckNeeded = a.param(UserApproval.AutoApproveKey).exists(_ == "true")
      if (!cfg.csrfEnabled || !isCsrfCheckNeeded)
        block
      else {
        val csrfVerifies = (for {
          queryToken <- a.param(CSRF.TokenName)
          sessionToken <- CSRF.getToken(req)
        } yield {
          Crypto.compareSignedTokens(queryToken, sessionToken.value)
        }) getOrElse (false)
        if (!csrfVerifies)
          throw new IllegalStateException("CSRF token check failed")
        else block
      }
    }
  }
}

private[grants] object UserExtractor {
  import securesocial.core.SecuredRequest
  def apply(r: SecuredRequest[_]) = {
    oauthorize.model.Oauth2User(UserId(r.user.identityId.userId, Option(r.user.identityId.providerId)))
  }
}
