package oauthorize.grants

import oauth2.spec._
import oauthorize.model._
import oauthorize.utils._
import oauthorize.service._
import scala.concurrent.Future
import scala.concurrent.ExecutionContext

class Oauth2RequestValidator(
  val config: Oauth2Config,
  val logger: Logging) {

  def getErrors(implicit r: OauthRequest, ctx: ExecutionContext): Option[Future[Err]] = {
    logger.debug("Global validation for: " + r)
    val res = getAuthorizeRequestError orElse
      getAccessTokenRequestError
    res.foreach(err => logger.warn(s"Rejected $r because of $err"))
    res.map(Future(_))
  }

  private def getAuthorizeRequestError(implicit r: OauthRequest) = {
    val invalid = r.path == config.authorizeEndpoint &&
      r.param(Req.response_type).map(v => v != ResponseType.code && v != ResponseType.token).getOrElse(true)
    if (invalid)
      Some(err(AuthzErrors.invalid_request, s"mandatory: ${Req.response_type} in [${ResponseType.code}, ${ResponseType.token}]"))
    else None
  }

  private def getAccessTokenRequestError(implicit r: OauthRequest) = {
    invalidAccessTokenEndpointMethod orElse
      invalidAccessTokenEndpointContentType orElse
      invalidAccessTokenGrantType
  }

  private def invalidAccessTokenEndpointMethod(implicit r: OauthRequest) = {
    if (r.path == config.accessTokenEndpoint && r.method != "POST") {
      Some(err(AuthzErrors.invalid_request, s"mandatory: HTTPS POST"))
    } else None
  }

  private def invalidAccessTokenEndpointContentType(implicit r: OauthRequest) = {
    if (r.path == config.accessTokenEndpoint && r.header("Content-Type").map(_.split(";")(0).trim != "application/x-www-form-urlencoded").getOrElse(true)) {
      Some(err(AuthzErrors.invalid_request, s"mandatory: Content-Type -> application/x-www-form-urlencoded"))
    } else None
  }

  private def invalidAccessTokenGrantType(implicit r: OauthRequest) = {
    if (r.path == config.accessTokenEndpoint && r.param(Req.grant_type).map(gt =>
      gt != GrantTypes.authorization_code &&
        gt != GrantTypes.refresh_token &&
        gt != GrantTypes.client_credentials &&
        gt != GrantTypes.password).getOrElse(true)) {
      Some(err(AuthzErrors.invalid_request, "invalid grant type"))
    } else None
  }
}