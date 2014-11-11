package oauthorize.playapp.grants

import play.api.mvc._
import play.api.mvc.Results._
import play.api.libs.json.Json
import oauthorize.model._
import oauthorize.service._
import oauthorize.grants._
import oauthorize.utils.BasicAuthentication
import json._
import oauthorize.playapp.csrf._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext
import securesocial.core.SecureSocial

class Oauth2RequestValidatorPlay(
  config: Oauth2Config,
  logger: Logging,
  validator: Oauth2RequestValidator)
  extends Oauth2BodyReaderFilter(logger) {

  private val renderingImplicits = new RenderingUtils(config)

  override def matches(r: OauthRequest) = validator.matches(r)
  
  override def bodyProcessor(a: OauthRequest, req: RequestHeader)(implicit ctx: ExecutionContext) = {
    logger.logInfo(s"proceed with global validation at: $a")
    validator.getErrors(a, ctx).map(maybeErr => maybeErr.map(renderingImplicits.renderErrorAsResult(_)))
  }
}

class AccessTokenEndpointPlay(
  config: Oauth2Config,
  logger: Logging,
  processor: AccessTokenEndpoint) extends Oauth2BodyReaderFilter(logger) {

  private val renderingImplicits = new RenderingUtils(config)
  import renderingImplicits._

  override def matches(r: OauthRequest) = processor.matches(r)
  
  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader)(implicit ctx: ExecutionContext) = {
    Option(processor.processAccessTokenRequest(oauthRequest, BasicAuthentication(oauthRequest)).map(_.fold(err => err, correct => correct)))
  }
}

class RefreshTokenEndpointPlay(
  config: Oauth2Config,
  logger: Logging,
  processor: RefreshTokenEndpoint) extends Oauth2BodyReaderFilter(logger) {

  private val renderingImplicits = new RenderingUtils(config)
  import renderingImplicits._
  
  override def matches(r: OauthRequest) = processor.matches(r)

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader)(implicit ctx: ExecutionContext) = {
    Option(processor.processRefreshTokenRequest(oauthRequest, BasicAuthentication(oauthRequest)).map(_.fold(err => err, correct => correct)))
  }
}

class ClientCredentialsGrantPlay(
  config: Oauth2Config,
  logger: Logging,
  processor: ClientCredentialsGrant) extends Oauth2BodyReaderFilter(logger) {

  private val renderingImplicits = new RenderingUtils(config)
  import renderingImplicits._
  
  override def matches(r: OauthRequest) = processor.matches(r)

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader)(implicit ctx: ExecutionContext) = {
    Option(processor.processClientCredentialsRequest(oauthRequest, BasicAuthentication(oauthRequest)).map(_.fold(err => err, correct => correct)))
  }
}

class AuthorizationCodePlay(
  config: Oauth2Config,
  logger: Logging,
  processor: AuthorizationCode) extends Oauth2BodyReaderFilter(logger) {

  private val renderingImplicits = new RenderingUtils(config)
  import renderingImplicits._
  
  override def matches(r: OauthRequest) = processor.matches(r)

  override def bodyProcessor(a: OauthRequest, req: RequestHeader)(implicit ctx: ExecutionContext) = {
    Option(processor.processAuthorizeRequest(a).map(_.fold(err => err, good => WithCsrf(req, good))))
  }
}

class ResourceOwnerCredentialsGrantPlay(
  config: Oauth2Config,
  logger: Logging,
  processor: ResourceOwnerCredentialsGrant) extends Oauth2BodyReaderFilter(logger) {

  private val renderingImplicits = new RenderingUtils(config)
  import renderingImplicits._
  
  override def matches(r: OauthRequest) = processor.matches(r)

  override def bodyProcessor(oauthRequest: OauthRequest, req: RequestHeader)(implicit ctx: ExecutionContext) = {
    Option(processor.processOwnerCredentialsRequest(oauthRequest, BasicAuthentication(oauthRequest)).map(_.fold(err => err, correct => correct)))
  }
}

class ImplicitGrantPlay(
  config: Oauth2Config,
  logger: Logging,
  processor: ImplicitGrant) extends Oauth2BodyReaderFilter(logger) with securesocial.core.SecureSocial {

  private val renderingImplicits = new RenderingUtils(config)
  import renderingImplicits._
  
  override def matches(r: OauthRequest) = processor.matches(r)

  override def bodyProcessor(a: OauthRequest, req: RequestHeader)(implicit ctx: ExecutionContext) = {
    def process(u: Oauth2User): SimpleResult = processor.processImplicitRequest(a, u).fold(err => err, good => WithCsrf(req, good))
    Some(secureInvocation(process, req))
  }

  private def secureInvocation(block: (Oauth2User) => Result, req: RequestHeader) = {
    (SecuredAction { implicit r => block(UserExtractor(r)) })(req).run
  }

}

class UserApprovalPlay(
  config: Oauth2Config,
  logger: Logging,
  store: Oauth2Store,
  processor: UserApproval) extends Oauth2BodyReaderFilter(logger) with SecureSocial {

  import oauth2.spec.Req._
  import oauthorize.utils._
  import oauth2.spec.AuthzErrors._
  import scala.concurrent.Await
  import scala.concurrent.duration._

  private val renderingImplicits = new RenderingUtils(config)
  import renderingImplicits._
  
  override def matches(r: OauthRequest) = processor.matches(r)

  override def bodyProcessor(a: OauthRequest, req: RequestHeader)(implicit ctx: ExecutionContext) = {
    logger.logInfo(s"processing user approval: $a");
    def lazyResult(u: Oauth2User) = {
      if ("POST" == a.method || a.param(UserApproval.AutoApproveKey).exists(_ == "true")) {
        lazyProcessApprove(a, u, req)
      } else displayUserApprovalPage(a, req)
    }
    Some(secureInvocation(lazyResult, req))
  }

  private def lazyProcessApprove(a: OauthRequest, u: Oauth2User, req: RequestHeader): SimpleResult = {
    CsrfCheck(req, a) {
      processor.processApprove(a, u)
    }.withSession(req.session - OauthorizeCsrfConf.TokenName)
  }

  def buildUserApprovalPage(authzReq: AuthzRequest, authzRequestJsonString: String, client: Oauth2Client, req: RequestHeader): SimpleResult = {
    Ok(views.html.oauthz.user_approval(authzReq, authzRequestJsonString, client, req))
  }

  private def displayUserApprovalPage(a: OauthRequest, req: RequestHeader): SimpleResult = {
    implicit val request = req
    (for {
      authzRequestJsonString <- a.param(UserApproval.AuthzRequestKey)
      authzReq <- processor.unmarshal(authzRequestJsonString)
      client <- store.getClient(authzReq.clientId)
    } yield {
      buildUserApprovalPage(authzReq, authzRequestJsonString, client, req)
    }) getOrElse ({
      logger.logError("Fatal error when initiating user approval after user authentication! The authorization code, authorization request or the client weren't found. Shouldn't have got here EVER, we're controlling the whole flow!")
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
