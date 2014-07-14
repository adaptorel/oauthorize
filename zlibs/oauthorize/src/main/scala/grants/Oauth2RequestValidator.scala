package oauthorize.grants

import oauth2.spec._
import oauthorize.model._
import oauthorize.utils._
import oauthorize.service._
import scala.concurrent.Future

trait Oauth2RequestValidator extends Dispatcher {

  this: Oauth2Defaults =>
    
  override def matches(request: OauthRequest) = true  

  def getErrors(implicit r: OauthRequest): Option[Future[Err]] = {
    val res = getAuthorizeRequestError orElse
      getAccessTokenRequestError
    res.map(err => debug(s"rejecting $r because of $err"))
    res.map(Future(_))
  }

  private def getAuthorizeRequestError(implicit r: OauthRequest) = {
    val invalid = r.path == authorizeEndpoint &&
      r.param(Req.response_type).map(v => v != ResponseType.code && v != ResponseType.token).getOrElse(true)
    if (invalid)
      Some(err(AuthzErrors.invalid_request, s"mandatory: ${Req.response_type} in [${ResponseType.code}, ${ResponseType.token}]"))
    else None
  }

  private def getAccessTokenRequestError(implicit r: OauthRequest) = {
    invalidAccessTokenMethod orElse
      invalidAccessTokenGrantType orElse
      invalidAccessTokenCodeParamMissing
  }

  private def invalidAccessTokenMethod(implicit r: OauthRequest) = {
    if (r.path == accessTokenEndpoint && r.method != "POST") {
      Some(err(AuthzErrors.invalid_request, s"mandatory: HTTPS POST"))
    } else None
  }

  private def invalidAccessTokenGrantType(implicit r: OauthRequest) = {
    if (r.path == accessTokenEndpoint && r.param(Req.grant_type).map(gt => gt != GrantTypes.authorization_code && gt != GrantTypes.refresh_token && gt != GrantTypes.client_credentials && gt != GrantTypes.password).getOrElse(true)) {
      Some(err(AuthzErrors.invalid_request, "invalid grant type"))
    } else None
  }

  private def invalidAccessTokenCodeParamMissing(implicit r: OauthRequest) = {
    if (r.path == accessTokenEndpoint && r.param(Req.grant_type).map(gt => gt == GrantTypes.authorization_code && !r.param(Req.code).isDefined).getOrElse(false)) {
      Some(err(AuthzErrors.invalid_request, s"mandatory: ${Req.code} parameter"))
    } else None
  }

}