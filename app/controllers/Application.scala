package app

import oauthorize.model._
import oauthorize.service._
import grants._
import grants.playimpl._
import play.api.mvc._
import play.api.mvc.Results.InternalServerError
import play.api.GlobalSettings

trait OauthMix extends Oauth2DefaultsPlay
  with InMemoryOauth2Store
  with DefaultAuthzCodeGenerator
  with BCryptPasswordEncoder

object Oauth extends OauthMix

object Oauth2RequestValidator extends Oauth2RequestValidatorPlay with OauthMix
object AuthorizationCodeGrant extends AuthorizationCodePlay with OauthMix
object ImplicitGrant extends ImplicitGrantPlay with OauthMix
object ClientCredentialsGrant extends ClientCredentialsGrantPlay with OauthMix
object AccessTokenEndpoint extends AccessTokenEndpointPlay with OauthMix
object RefreshTokenEndpoint extends RefreshTokenEndpointPlay with OauthMix
object ResourceOwnerCredentialsGrant extends ResourceOwnerCredentialsGrantPlay with OauthMix
  with UserStore { override def getUser(id: UserId) = throw new UnsupportedOperationException }
object UserApprovalEndpoint extends UserApprovalPlay with OauthMix

class Oauth2Filters extends WithFilters(
  Oauth2RequestValidator,
  AuthorizationCodeGrant,
  ImplicitGrant,
  ClientCredentialsGrant,
  ResourceOwnerCredentialsGrant,
  AccessTokenEndpoint,
  RefreshTokenEndpoint,
  UserApprovalEndpoint) with Oauth2GlobalErorrHandler

trait Oauth2GlobalErorrHandler extends GlobalSettings {
  import oauthorize.utils.err
  import oauth2.spec._
  import grants.playimpl.json._
  import scala.concurrent.Future
  import play.api.libs.json.Json
  override def onError(request: RequestHeader, ex: Throwable) = {
    val resp = err(AccessTokenErrors.server_error, "internal server error", StatusCodes.InternalServerError)
    Future.successful(InternalServerError(Json.toJson(resp)))
  }
}

trait PlayExecutionContextProvider extends ExecutionContextProvider {
  override val oauthExecutionContext = play.api.libs.concurrent.Execution.Implicits.defaultContext
}

trait PlayLogging extends Logging {
  import play.api.Logger
  lazy val oauthorizeLogger = Logger("oauthorize")

  override def debug(message: String) = if (oauthorizeLogger.isDebugEnabled) oauthorizeLogger.debug(message)
  override def warn(message: String) = if (oauthorizeLogger.isWarnEnabled) oauthorizeLogger.warn(message)
  override def logInfo(message: String) = if (oauthorizeLogger.isInfoEnabled) oauthorizeLogger.info(message)
  override def logError(message: String) = if (oauthorizeLogger.isErrorEnabled) oauthorizeLogger.error(message)
  override def logError(message: String, t: Throwable) = if (oauthorizeLogger.isErrorEnabled) oauthorizeLogger.error(message, t)
}

trait Oauth2DefaultsPlay extends Oauth2Defaults with PlayLogging with PlayExecutionContextProvider