package oauthorize.playapp

import oauthorize.model._
import oauthorize.service._
import grants._
import play.api.mvc._
import play.api.mvc.Results.InternalServerError
import play.api.GlobalSettings

trait OauthMix extends Oauth2DefaultsPlay
  with InMemoryOauth2Store
  with DefaultAuthzCodeGenerator
  with BCryptClientSecretHasher
  with BCryptUserPasswordHasher
  with DefaultTenantResolver

object Oauth extends OauthMix

object Oauth2RequestValidator extends Oauth2RequestValidatorPlay with OauthMix
object AuthorizationCodeGrant extends AuthorizationCodePlay with OauthMix
object ImplicitGrant extends ImplicitGrantPlay with OauthMix
object ClientCredentialsGrant extends ClientCredentialsGrantPlay with OauthMix
object AccessTokenEndpoint extends AccessTokenEndpointPlay with OauthMix
object RefreshTokenEndpoint extends RefreshTokenEndpointPlay with OauthMix
object ResourceOwnerCredentialsGrant extends ResourceOwnerCredentialsGrantPlay with OauthMix with SecureSocialUserStore 
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
  import grants.json._
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

trait SecureSocialUserStore extends UserStore {
  import securesocial.core._
  override def getUser(id: UserId) = {
    UserService.find(IdentityId(id.value, id.provider.getOrElse("userpass")))
      .map(u => Oauth2User(UserId(u.identityId.userId, Option(u.identityId.providerId)), u.passwordInfo.map(i => SecretInfo(i.password, i.salt))))
  }
}

import securesocial.core._
import securesocial.core.providers.utils._

/**
 * The default password hasher based on BCrypt.
 */
class BCryptPasswordHasher(app: play.api.Application) extends PasswordHasher {

  override def id = PasswordHasher.BCryptHasher

  /**
   * Hashes a password. This implementation does not return the salt because it is not needed
   * to verify passwords later.  Other implementations might need to return it so it gets saved in the
   * backing store.
   *
   * @param plainPassword the password to hash
   * @return a PasswordInfo containing the hashed password.
   */
  def hash(plainPassword: String): PasswordInfo = {
    PasswordInfo(id, Oauth.hashUserSecret(SecretInfo(plainPassword)))
  }

  /**
   * Checks if a password matches the hashed version
   *
   * @param passwordInfo the password retrieved from the backing store (by means of UserService)
   * @param suppliedPassword the password supplied by the user trying to log in
   * @return true if the password matches, false otherwise.
   */
  def matches(passwordInfo: PasswordInfo, suppliedPassword: String): Boolean = {
    Oauth.userPasswordMatches(suppliedPassword, SecretInfo(passwordInfo.password))
  }
}