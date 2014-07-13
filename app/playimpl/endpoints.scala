package grants.playimpl

import play.api.mvc._
import play.api.mvc.Results._
import oauthorize.model._
import oauthorize.service._
import oauthorize.grants._
import json._
import scala.concurrent.Future
import play.api.libs.json.Json

trait OauthRequestValidatorPlay extends BodyReaderFilter with OauthRequestValidator with Dispatcher with RenderingUtils {
  this: OauthConfig with Oauth2Store with AuthzCodeGenerator with ExecutionContextProvider =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    println(s" -- processing $a")
    getErrors(a).map(e => Future(renderErrorAsResult(e)))
  }
  override def matches(request: OauthRequest) = true
}

trait AccessTokenEndpointPlay extends BodyReaderFilter with AccessTokenEndpoint with RenderingUtils {
  this: OauthConfig with PasswordEncoder with Oauth2Store with AuthzCodeGenerator with ExecutionContextProvider =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processAccessTokenRequest(oauthRequest, BasicAuthentication(req)).map(_.fold(err => err, correct => correct)))
  }
}

trait ClientCredentialsGrantPlay extends BodyReaderFilter with ClientCredentialsGrant with RenderingUtils {
  this: OauthConfig with PasswordEncoder with Oauth2Store with AuthzCodeGenerator with ExecutionContextProvider =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processClientCredentialsRequest(oauthRequest, BasicAuthentication(req)).map(_.fold(err => err, correct => correct)))
  }
}

trait AuthorizationCodePlay extends BodyReaderFilter with AuthorizationCode with RenderingUtils {
  this: OauthConfig with Oauth2Store with AuthzCodeGenerator with ExecutionContextProvider =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    Option(processAuthorizeRequest(a).map(_.fold(err => err, good => good)))
  }
}

trait ImplicitGrantPlay extends BodyReaderFilter with ImplicitGrant with RenderingUtils {
  this: OauthConfig with Oauth2Store with AuthzCodeGenerator with ExecutionContextProvider =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) =
    Option(processImplicitRequest(a).map(_.fold(err => err, good => transformReponse(good))))
}

trait UserApprovalPlay extends BodyReaderFilter with UserApproval with RenderingUtils with securesocial.core.SecureSocial {
  this: OauthConfig with Oauth2Store =>

  import oauth2.spec.Req._
  import oauthorize.utils._
  import oauth2.spec.AuthzErrors._
  import scala.concurrent.Await
  import scala.concurrent.duration._

  override def unmarshal(authzRequestJsonString: String) = Json.parse(authzRequestJsonString).asOpt[AuthzRequest]

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    //def lazyResult(u: Oauth2User) = if ("GET" == a.method) displayUserApprovalPage(a) else lazyProcessApprove(a, u)
    println(" --- approve endpoint with " + a);
    def lazyResult(u: Oauth2User) =
      if ("POST" == a.method || a.param(UserApproval.AutoApproveKey).map(_ == "true").getOrElse(false))
        lazyProcessApprove(a, u)
      else displayUserApprovalPage(a)
    Some(secureInvocation(lazyResult, req))
  }

  private def lazyProcessApprove(a: OauthRequest, u: Oauth2User) = {
    val res = processApprove(a, u)
    Redirect(res.uri, res.params.map(z => (z._1 -> Seq(z._2))), 302)
  }

  private def displayUserApprovalPage(a: OauthRequest) = {
    (for {
      authzCode <- a.param(code)
      authzRequestJsonString <- a.param(UserApproval.AuthzRequestKey)
      authzReq <- unmarshal(authzRequestJsonString)
      client <- getClient(authzReq.clientId)
    } yield {
      Ok(views.html.user_approval(authzCode, authzReq, authzRequestJsonString, client))
    }) getOrElse ({
      println("Fatal error when initiating user approval after user authentication! The authorization code, authorization request or the client weren't found. Shouldn't have got here EVER, we're controlling the whole flow!");
      renderErrorAsResult(err(server_error, 500))
    })
  }

  val WaitTime = 5 seconds
  private def secureInvocation(block: (Oauth2User) => Result, req: RequestHeader) = {
    (SecuredAction { implicit r => block(Oauth2User(r)) })(req).run
  }

  private object Oauth2User {
    import securesocial.core.SecuredRequest
    import securesocial.core.providers.UsernamePasswordProvider.UsernamePassword
    def apply(r: SecuredRequest[_]) = {
      val emailOrElseId = if (r.user.identityId.providerId == UsernamePassword) r.user.identityId.userId else r.user.email.getOrElse(r.user.identityId.userId)
      oauthorize.model.Oauth2User(UserId(emailOrElseId, Option(r.user.identityId.providerId)))
    }
  }
}