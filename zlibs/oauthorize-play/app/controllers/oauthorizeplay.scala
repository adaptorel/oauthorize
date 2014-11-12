package oauthorize.playapp

import scala.concurrent.Future

import defaults._
import grants.json._
import oauth2.spec._
import oauthorize.model._
import oauthorize.service._
import oauthorize.utils.err
import play.api._
import play.api.libs.json.Json
import play.api.mvc.RequestHeader
import play.api.mvc.Results._
import securesocial.core._
import securesocial.core.providers.utils.PasswordHasher

trait Oauth2GlobalErorrHandler extends GlobalSettings {
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
  override def info(message: String) = if (oauthorizeLogger.isInfoEnabled) oauthorizeLogger.info(message)
  override def error(message: String) = if (oauthorizeLogger.isErrorEnabled) oauthorizeLogger.error(message)
  override def error(message: String, t: Throwable) = if (oauthorizeLogger.isErrorEnabled) oauthorizeLogger.error(message, t)
}

class SecureSocialUserStore extends UserStore {
  import securesocial.core._
  override def getUser(id: UserId) = {
    UserService.find(IdentityId(id.value, id.provider.getOrElse("userpass")))
      .map(u => Oauth2User(UserId(u.identityId.userId, Option(u.identityId.providerId)), u.passwordInfo.map(i => SecretInfo(i.password, i.salt))))
  }
}

class BCryptPasswordHasher(app: play.api.Application) extends PasswordHasher {
  
  import defaults._

  override def id = PasswordHasher.BCryptHasher

  def hash(plainPassword: String): PasswordInfo = {
    PasswordInfo(id, userPasswordHasher.hashSecret(SecretInfo(plainPassword)).secret)
  }

  def matches(passwordInfo: PasswordInfo, suppliedPassword: String): Boolean = {
    userPasswordHasher.secretMatches(suppliedPassword, SecretInfo(passwordInfo.password))
  }
}