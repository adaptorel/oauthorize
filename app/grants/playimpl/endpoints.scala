package grants.playimpl

import play.api.mvc._
import play.api.mvc.Results._
import oauthze.model._
import oauthze.service._
import grants._
import json._
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import scala.concurrent.Future

trait OauthRequestValidatorPlay extends BodyReaderFilter with OauthRequestValidator with Dispatcher with RenderingUtils {
  this: OauthConfig with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    println(s" -- processing $a")
    getErrors(a).map(e => Future(renderErrorAsResult(e)))
  }
  override def matches(request: OauthRequest) = true
}

trait AccessTokenEndpointPlay extends BodyReaderFilter with AccessTokenEndpoint with RenderingUtils {
  this: OauthConfig with PasswordEncoder with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processAccessTokenRequest(oauthRequest, BasicAuthentication(req)).map(_.fold(err => err, correct => correct)))
  }
}

trait ClientCredentialsGrantPlay extends BodyReaderFilter with ClientCredentialsGrant with RenderingUtils {
  this: OauthConfig with PasswordEncoder with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processClientCredentialsRequest(oauthRequest, BasicAuthentication(req)).map(_.fold(err => err, correct => correct)))
  }
}

trait AuthorizationCodePlay extends BodyReaderFilter with AuthorizationCode with RenderingUtils {
  this: OauthConfig with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    Option(processAuthorizeRequest(a).map(_.fold (err => err, good => good)))
  }
}

trait ImplicitGrantPlay extends BodyReaderFilter with ImplicitGrant with RenderingUtils {
  this: OauthConfig with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) =
    Option(processImplicitRequest(a).map(_.fold(err => err, good => transformReponse(good))))
}

trait UserApprovalPlay extends BodyReaderFilter with UserApproval with RenderingUtils with securesocial.core.SecureSocial {
  this: OauthConfig with OauthClientStore =>

  import oauth2.spec.Req._
  import oauthze.utils._
  import oauth2.spec.AuthzErrors._
  import scala.concurrent.Await
  import scala.concurrent.duration._

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    def lazyResult = if ("GET" == a.method) displayUserApprovalPage(a) else lazyProcessApprove(a)
    Some(secureInvocation(lazyResult, req))
  }

  private def lazyProcessApprove(a: OauthRequest) = {
    val res = processApprove(a)
    Redirect(res.uri, res.params.map(z => (z._1 -> Seq(z._2))), 302)
  }

  private def displayUserApprovalPage(a: OauthRequest) = {
    (for {
      authzCode <- a.param(code)
      authzReq <- getAuthzRequest(authzCode)
      client <- getClient(authzReq.clientId)
    } yield {
      Ok(views.html.user_approval(authzCode, authzReq, client))
    }) getOrElse ({
      println("Fatal error when initiating user approval after user authentication! The authorization code, authorization request or the client weren't found. Shouldn't have got here EVER, we're controlling the whole flow!");
      renderErrorAsResult(err(server_error, 500))
    })
  }

  val WaitTime = 5 seconds
  private def secureInvocation(block: => Result, req: RequestHeader) = {
    (SecuredAction { block })(req).run
  }
}