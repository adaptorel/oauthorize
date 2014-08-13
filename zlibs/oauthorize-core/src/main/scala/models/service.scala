package oauthorize.service

import oauthorize.utils._
import oauthorize.model._
import java.util.UUID
import java.security.SecureRandom
import org.mindrot.jbcrypt.BCrypt

trait ClientSecretHasher {
  def hashClientSecret(info: SecretInfo): SecretInfo
  def clientSecretMatches(rawSecret: String, info: SecretInfo): Boolean
}

trait Sha256ClientSecretHasher extends ClientSecretHasher {
  lazy val hasher = new Sha256SecretHasher {}
  override def hashClientSecret(info: SecretInfo): SecretInfo = SecretInfo(hasher.hashSecret(info), info.salt)
  override def clientSecretMatches(rawSecret: String, info: SecretInfo): Boolean = hasher.secretMatches(rawSecret, info)
}

trait BCryptClientSecretHasher extends ClientSecretHasher {
  val roundsNo = 10
  lazy val hasher = new BCryptSecretHasher { override val rounds = roundsNo }
  override def hashClientSecret(info: SecretInfo): SecretInfo = SecretInfo(hasher.hashSecret(info), info.salt)
  override def clientSecretMatches(rawSecret: String, info: SecretInfo): Boolean = hasher.secretMatches(rawSecret, info)
}

trait Tenant {
  def name: String
}

object TenantImplicits {
  implicit val DefaultTenant = new Tenant { override val name = "__DEFAULT_TENANT__" }
}

trait Oauth2Store {
  def storeClient(client: Oauth2Client)(implicit tenant: Tenant): Oauth2Client
  def getClient(clientId: String)(implicit tenant: Tenant): Option[Oauth2Client]
  def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest)(implicit tenant: Tenant): AuthzRequest
  def getAuthzRequest(authzCode: String)(implicit tenant: Tenant): Option[AuthzRequest]
  def storeTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client)(implicit tenant: Tenant): AccessAndRefreshTokens
  def getAccessToken(value: String)(implicit tenant: Tenant): Option[AccessToken]
  def getRefreshToken(value: String)(implicit tenant: Tenant): Option[RefreshToken]
  def markForRemoval(item: Expirable, key: Option[String])
  def findAuthzRequestsToEvict(offset: Int, howMany: Int): Seq[AuthzRequest]
  def findAccessTokensToEvict(offset: Int, howMany: Int): Seq[AccessToken]
  def findRefreshTokensToEvict(offset: Int, howMany: Int): Seq[RefreshToken]
}

trait Oauth2Config {
  def authorizeEndpoint: String = "/oauth/authorize"
  def accessTokenEndpoint: String = "/oauth/token"
  def userApprovalEndpoint: String = "/oauth/approve"
  def authzCodeValiditySeconds: Long = 60
  def evictorIntervalSeconds: Long = 60 * 10 // seconds, every 10 minutes by default
}

trait Evictor {
  def evictAll: Int
  def evictAuthzCodes(offset: Int): Int
  def evictAccessTokens(offset: Int): Int
  def evictRefreshTokens(offset: Int): Int
}

trait Logging {
  def debug(message: String)
  def warn(message: String)
  def logInfo(message: String)
  def logError(message: String)
  def logError(message: String, t: Throwable)
}

trait Dispatcher {
  def matches(request: OauthRequest): Boolean
}

trait ExecutionContextProvider {
  import scala.concurrent.ExecutionContext
  implicit def oauthExecutionContext: ExecutionContext
}

trait Oauth2Defaults extends Oauth2Config with ExecutionContextProvider with Logging

trait UserStore {
  def getUser(id: UserId): Option[Oauth2User]
}

trait UserPasswordHasher {
  def hashUserSecret(info: SecretInfo): String
  def userPasswordMatches(rawPassword: String, info: SecretInfo): Boolean
}

trait BCryptUserPasswordHasher extends UserPasswordHasher with BCryptSecretHasher {
  override def hashUserSecret(info: SecretInfo): String = hashSecret(info)
  override def userPasswordMatches(rawPassword: String, info: SecretInfo): Boolean = secretMatches(rawPassword, info)
}

trait AuthzCodeGenerator {
  def generateCode(authzRequest: AuthzRequest): String
  def generateAccessToken(oauthClient: Oauth2Client, scope: Seq[String], userId: Option[UserId]): AccessToken
  def generateRefreshToken(oauthClient: Oauth2Client, scope: Seq[String], userId: Option[UserId]): RefreshToken
}

trait DefaultAuthzCodeGenerator extends AuthzCodeGenerator {
  this: ClientSecretHasher =>
  override def generateCode(authzRequest: AuthzRequest) = newToken
  override def generateAccessToken(oauthClient: Oauth2Client, authScope: Seq[String], userId: Option[UserId]) = AccessToken(newToken, oauthClient.clientId, authScope, oauthClient.accessTokenValidity, System.currentTimeMillis, userId)
  override def generateRefreshToken(oauthClient: Oauth2Client, tokenScope: Seq[String], userId: Option[UserId]) = RefreshToken(newToken, oauthClient.clientId, tokenScope, oauthClient.refreshTokenValidity, System.currentTimeMillis, userId)
  def newToken = hashClientSecret(SecretInfo(UUID.randomUUID().toString)).secret
}

trait DefaultEvictor extends Evictor {
  this: Oauth2Config with Oauth2Store with Logging =>

  val batchSize = 100
  override def evictAuthzCodes(offset: Int): Int = {
    val items = findAuthzRequestsToEvict(offset, batchSize)
    items.foreach(req => markForRemoval(req, req.code))
    if (items.size > 0) {
      val evicted = evictAuthzCodes(offset + batchSize)
      items.size + evicted
    } else items.size
  }
  override def evictAccessTokens(offset: Int): Int = {
    val items = findAccessTokensToEvict(offset, batchSize)
    items.foreach(t => markForRemoval(t, Option(t.value)))
    if (items.size > 0) {
      val evicted = evictAccessTokens(offset + batchSize)
      items.size + evicted
    } else items.size
  }
  override def evictRefreshTokens(offset: Int): Int = {
    val items = findRefreshTokensToEvict(offset, batchSize)
    items.foreach(t => markForRemoval(t, Option(t.value)))
    if (items.size > 0) {
      val evicted = evictRefreshTokens(offset + batchSize)
      items.size + evicted
    } else items.size
  }
  override def evictAll = {
    debug("running eviction job for authz codes")
    val c = evictAuthzCodes(0)
    debug(s"evicted $c authz codes")
    debug("runing eviction job for access tokens")
    val at = evictAccessTokens(0)
    debug(s"evicted $at access tokens")
    debug("running eviction job for refresh tokens")
    val rt = evictRefreshTokens(0)
    debug(s"evicted $rt refresh tokens")
    c + at + rt
  }
}

trait Sha256SecretHasher {
  def hashSecret(info: SecretInfo): String = sha256(info.salt.getOrElse("") + info.secret)
  def secretMatches(rawPassword: String, info: SecretInfo): Boolean = constantTimeEquals(sha256(info.salt.getOrElse("") + rawPassword), info.secret)
  private def constantTimeEquals(a: String, b: String) = {
    if (a.length != b.length) {
      false
    } else {
      var equal = 0
      for (i <- 0 until a.length) {
        equal |= a(i) ^ b(i)
      }
      equal == 0
    }
  }
}

trait BCryptSecretHasher {
  private val rnd = new SecureRandom
  val rounds = 10
  private def paddedRounds = { rounds.toString.reverse.padTo(2, "0").reverse.mkString }
  private def prefix = "$2a$" + paddedRounds + "$"
  def hashSecret(info: SecretInfo): String = BCrypt.hashpw(info.secret, BCrypt.gensalt(rounds, rnd)).substring(7)
  def secretMatches(rawPassword: String, info: SecretInfo): Boolean = {
    (for {
      raw <- Option(rawPassword)
      enc <- Option(info.secret)
    } yield {
      enc.length == (60 - prefix.length) && BCrypt.checkpw(rawPassword, prefix + info.secret)
    }) getOrElse (false)
  }
}

/**
 * Allows creation of more delegates in case you don't want the default one
 */
trait InMemoryStoreDelegate extends Oauth2Store {
  private val oauthClientStore = scala.collection.mutable.Map[String, Oauth2Client]()
  private val authzCodeStore = scala.collection.mutable.Map[String, AuthzRequest]()
  private val implicitTokenStore = scala.collection.mutable.Map[String, AccessToken]()
  private val accessTokenStore = scala.collection.mutable.Map[String, AccessToken]()
  private val refreshTokenStore = scala.collection.mutable.Map[String, RefreshToken]()

  override def storeClient(client: Oauth2Client)(implicit tenant: Tenant) = { oauthClientStore.put(client.clientId, client); client }
  override def getClient(clientId: String)(implicit tenant: Tenant) = oauthClientStore.get(clientId)
  override def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest)(implicit tenant: Tenant) = { authzCodeStore.put(authzCode, authzRequest); authzRequest }
  override def getAuthzRequest(authzCode: String)(implicit tenant: Tenant) = authzCodeStore.get(authzCode)
  override def storeTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client)(implicit tenant: Tenant) = {
    accessTokenStore.put(accessAndRefreshTokens.accessToken.value, accessAndRefreshTokens.accessToken)
    accessAndRefreshTokens.refreshToken.foreach(t => refreshTokenStore.put(t.value, t))
    accessAndRefreshTokens
  }
  override def getAccessToken(value: String)(implicit tenant: Tenant) = accessTokenStore.find(t => t._1 == value).map(_._2)
  override def getRefreshToken(value: String)(implicit tenant: Tenant) = refreshTokenStore.find(t => t._1 == value).map(_._2)
  override def markForRemoval(item: Expirable, key: Option[String]) = {
    item match {
      case ar: AuthzRequest => key.foreach(authzCodeStore.remove(_))
      case at: AccessToken => accessTokenStore.remove(at.value)
      case rt: RefreshToken => refreshTokenStore.remove(rt.value)
      case _ => throw new IllegalArgumentException(s"Eviction not supported for item '$item'")
    }
  }
  override def findAuthzRequestsToEvict(offset: Int, howMany: Int): Seq[AuthzRequest] = authzCodeStore.filter(c => c._2.isExpired).map(_._2).toSeq
  override def findAccessTokensToEvict(offset: Int, howMany: Int): Seq[AccessToken] = accessTokenStore.filter(c => c._2.isExpired).map(_._2).toSeq
  override def findRefreshTokensToEvict(offset: Int, howMany: Int): Seq[RefreshToken] = refreshTokenStore.filter(c => c._2.isExpired).map(_._2).toSeq
}

private object DefaultInMemoryStoreDelegate extends InMemoryStoreDelegate

trait InMemoryOauth2Store extends Oauth2Store {
  lazy val delegate: Oauth2Store = DefaultInMemoryStoreDelegate
  import TenantImplicits.DefaultTenant
  override def storeClient(client: Oauth2Client)(implicit tenant: Tenant) = delegate.storeClient(client)
  override def getClient(clientId: String)(implicit tenant: Tenant) = delegate.getClient(clientId)
  override def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest)(implicit tenant: Tenant) = delegate.storeAuthzRequest(authzCode, authzRequest)
  override def getAuthzRequest(authzCode: String)(implicit tenant: Tenant) = delegate.getAuthzRequest(authzCode)
  override def storeTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client)(implicit tenant: Tenant) = delegate.storeTokens(accessAndRefreshTokens, oauthClient)
  override def getAccessToken(value: String)(implicit tenant: Tenant) = delegate.getAccessToken(value)
  override def getRefreshToken(value: String)(implicit tenant: Tenant) = delegate.getRefreshToken(value)
  override def markForRemoval(item: Expirable, key: Option[String]) = delegate.markForRemoval(item, key)
  override def findAuthzRequestsToEvict(offset: Int, howMany: Int): Seq[AuthzRequest] = delegate.findAuthzRequestsToEvict(offset, howMany)
  override def findAccessTokensToEvict(offset: Int, howMany: Int): Seq[AccessToken] = delegate.findAccessTokensToEvict(offset, howMany)
  override def findRefreshTokensToEvict(offset: Int, howMany: Int): Seq[RefreshToken] = delegate.findRefreshTokensToEvict(offset, howMany)
}