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

trait AuthorizationCodePlay extends Oauth2BodyReaderFilter with AuthorizationCode with RenderingUtils {
  this: Oauth2Defaults with Oauth2Store with AuthzCodeGenerator =>

  override def bodyProcessor(a: OauthRequest, req: RequestHeader) = {
    Option(processAuthorizeRequest(a).map(_.fold(err => err, good => good)))
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
    def process(u: Oauth2User): SimpleResult = processImplicitRequest(a, u).fold(err => err, good => good)
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
        lazyProcessApprove(a, u)
      else displayUserApprovalPage(a)
    Some(secureInvocation(lazyResult, req))
  }

  private def lazyProcessApprove(a: OauthRequest, u: Oauth2User): SimpleResult = {
    processApprove(a, u)
  }

  private def displayUserApprovalPage(a: OauthRequest): SimpleResult = {
    (for {
      authzRequestJsonString <- a.param(UserApproval.AuthzRequestKey)
      authzReq <- unmarshal(authzRequestJsonString)
      client <- getClient(authzReq.clientId)
    } yield {
      Ok(views.html.oauthz.user_approval(authzReq, authzRequestJsonString, client))
    }) getOrElse ({
      logError("Fatal error when initiating user approval after user authentication! The authorization code, authorization request or the client weren't found. Shouldn't have got here EVER, we're controlling the whole flow!")
      err(server_error, 500)
    })
  }

  private def secureInvocation(block: (Oauth2User) => Result, req: RequestHeader) = {
    (SecuredAction { implicit r => block(UserExtractor(r)) })(req).run
  }
}

private[grants] object UserExtractor {
  import securesocial.core.SecuredRequest
  def apply(r: SecuredRequest[_]) = {
    oauthorize.model.Oauth2User(UserId(r.user.identityId.userId, Option(r.user.identityId.providerId)))
  }
}
