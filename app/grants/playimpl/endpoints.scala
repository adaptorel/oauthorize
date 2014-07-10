package grants.playimpl

import play.api.mvc._
import play.api.mvc.Results._
import scala.concurrent.Future
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import oauthze.model._
import oauthze.service._
import grants._
import play.api.libs.json.Json
import json._
import oauth2.spec.AuthzErrors

trait OauthRequestValidatorPlay extends BodyReaderFilter with OauthRequestValidator with Dispatcher with RenderingUtils {
  this: OauthConfig with OauthClientStore with AuthzCodeGenerator =>
    
  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    println(s" -- processing $a")
    getErrors(a).map(renderErrorAsResult)
  }
  override def matches(request: OauthRequest) = true
}

trait AccessTokenEndpointPlay extends BodyReaderFilter with AccessTokenEndpoint with RenderingUtils {
  this: OauthConfig with PasswordEncoder with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processAccessTokenRequest(oauthRequest, BasicAuthentication(req)) match {
      case Left(err) => err
      case Right(res) => res
    })
  }
}

trait ClientCredentialsGrantPlay extends BodyReaderFilter with ClientCredentialsGrant with RenderingUtils {
  this: OauthConfig with PasswordEncoder with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader) = {
    Option(processClientCredentialsRequest(oauthRequest, BasicAuthentication(req)) match {
      case Left(err) => err
      case Right(res) => res
    })
  }
}

trait AuthorizationCodePlay extends BodyReaderFilter with AuthorizationCode with RenderingUtils {
  this: OauthConfig with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    Option(processAuthorizeRequest(a) fold (err => err, good => good))
  }
}

trait UserApprovalPlay extends BodyReaderFilter with UserApproval with RenderingUtils {
  this: OauthConfig with OauthClientStore =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) =
    Option(processApprove(a)) map { res => Redirect(res.uri, res.params.map(z => (z._1 -> Seq(z._2))), 302) }
}

trait ImplicitGrantPlay extends BodyReaderFilter with ImplicitGrant with RenderingUtils {
  this: OauthConfig with OauthClientStore with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) =
    Option(processImplicitRequest(a).fold(err => err, good => transformReponse(good)))

}