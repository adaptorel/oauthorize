package oauthorize.service

import oauthorize.utils._
import oauthorize.model._
import oauthorize.hash._
import java.util.UUID
import java.security.SecureRandom
import org.mindrot.jbcrypt.BCrypt
import scala.concurrent.{ Future, ExecutionContext }

trait ClientSecretHasher extends SecretHasher
class Sha256ClientSecretHasher extends HasherDelegate(new Sha256Hasher) with ClientSecretHasher
class BCryptClientSecretHasher(val rounds: Int) extends HasherDelegate(new BCryptHasher(rounds)) with ClientSecretHasher

trait Tenant {
  def name: String
}

object TenantImplicits {
  implicit val DefaultTenant = new Tenant { override val name = "__DEFAULT_TENANT__" }
}

trait Oauth2Store {
  def storeClient(client: Oauth2Client)(implicit ec: ExecutionContext, tenant: Tenant): Future[Oauth2Client]
  def getClient(clientId: String)(implicit ec: ExecutionContext, tenant: Tenant): Future[Option[Oauth2Client]]
  def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest)(implicit ec: ExecutionContext, tenant: Tenant): Future[AuthzRequest]
  def getAuthzRequest(authzCode: String)(implicit ec: ExecutionContext, tenant: Tenant): Future[Option[AuthzRequest]]
  def storeTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client)(implicit ec: ExecutionContext, tenant: Tenant): Future[AccessAndRefreshTokens]
  def getAccessToken(value: String)(implicit ec: ExecutionContext, tenant: Tenant): Future[Option[AccessToken]]
  def getRefreshToken(value: String)(implicit ec: ExecutionContext, tenant: Tenant): Future[Option[RefreshToken]]
  def markForRemoval(item: Expirable, key: Option[String])(implicit ec: ExecutionContext, tenant: Tenant): Future[Unit]
}

trait Oauth2Config {
  def authorizeEndpoint: String = "/oauth/authorize"
  def accessTokenEndpoint: String = "/oauth/token"
  def userApprovalEndpoint: String = "/oauth/approve"
  def authzCodeValiditySeconds: Long = 60
  def evictorIntervalSeconds: Long = 60 * 10 // seconds, every 10 minutes by default
}

trait Logging {
  def debug(message: String)
  def warn(message: String)
  def info(message: String)
  def error(message: String)
  def error(message: String, t: Throwable)
}

trait ExecutionContextProvider {
  import scala.concurrent.ExecutionContext
  implicit def oauthExecutionContext: ExecutionContext
}

trait UserStore {
  def getUser(id: UserId)(implicit ec: ExecutionContext, tenant: Tenant): Future[Option[Oauth2User]]
}

trait UserPasswordHasher extends SecretHasher
class BCryptUserPasswordHasher(val rounds: Int) extends HasherDelegate(new BCryptHasher(rounds)) with UserPasswordHasher

trait SecretHasher {
  def hashSecret(info: SecretInfo): SecretInfo
  def secretMatches(rawSecret: String, info: SecretInfo): Boolean
}

class HasherDelegate(val hasher: Hasher) extends SecretHasher {
  override def hashSecret(info: SecretInfo): SecretInfo = SecretInfo(hasher.hashSecret(info), info.salt)
  override def secretMatches(rawSecret: String, info: SecretInfo): Boolean = hasher.secretMatches(rawSecret, info)
}

trait TokenGenerator {
  def generateCode(authzRequest: AuthzRequest): String
  def generateAccessToken(oauthClient: Oauth2Client, scope: Seq[String], userId: Option[UserId]): AccessToken
  def generateRefreshToken(oauthClient: Oauth2Client, scope: Seq[String], userId: Option[UserId]): RefreshToken
}

class DefaultTokenGenerator(val hasher: Option[Hasher]) extends TokenGenerator {
  override def generateCode(authzRequest: AuthzRequest) = newToken
  override def generateAccessToken(oauthClient: Oauth2Client, authScope: Seq[String], userId: Option[UserId]) = AccessToken(newToken, oauthClient.clientId, authScope, oauthClient.accessTokenValidity, System.currentTimeMillis, userId)
  override def generateRefreshToken(oauthClient: Oauth2Client, tokenScope: Seq[String], userId: Option[UserId]) = RefreshToken(newToken, oauthClient.clientId, tokenScope, oauthClient.refreshTokenValidity, System.currentTimeMillis, userId)
  def newToken = {
    val token = UUID.randomUUID().toString
    hasher match {
      case None => token
      case Some(h) => h.hashSecret(SecretInfo(token))
    }
  }
}

/**
 * Allows creation of more delegates in case you don't want the default one
 */
class InMemoryStoreDelegate extends Oauth2Store {
  private val oauthClientStore = scala.collection.mutable.Map[String, Oauth2Client]()
  private val authzCodeStore = scala.collection.mutable.Map[String, AuthzRequest]()
  private val implicitTokenStore = scala.collection.mutable.Map[String, AccessToken]()
  private val accessTokenStore = scala.collection.mutable.Map[String, AccessToken]()
  private val refreshTokenStore = scala.collection.mutable.Map[String, RefreshToken]()

  override def storeClient(client: Oauth2Client)(implicit ec: ExecutionContext, tenant: Tenant) = Future {
    oauthClientStore.put(client.clientId, client); client
  }
  override def getClient(clientId: String)(implicit ec: ExecutionContext, tenant: Tenant) = Future {
    oauthClientStore.get(clientId)
  }
  override def storeAuthzRequest(
    authzCode: String,
    authzRequest: AuthzRequest)(implicit ec: ExecutionContext, tenant: Tenant) = Future {
    authzCodeStore.put(authzCode, authzRequest); authzRequest
  }
  override def getAuthzRequest(authzCode: String)(implicit ec: ExecutionContext, tenant: Tenant) = Future {
    authzCodeStore.get(authzCode)
  }
  override def storeTokens(
    accessAndRefreshTokens: AccessAndRefreshTokens,
    oauthClient: Oauth2Client)(implicit ec: ExecutionContext, tenant: Tenant) = Future {
    accessTokenStore.put(accessAndRefreshTokens.accessToken.value, accessAndRefreshTokens.accessToken)
    accessAndRefreshTokens.refreshToken.foreach(t => refreshTokenStore.put(t.value, t))
    accessAndRefreshTokens
  }
  override def getAccessToken(value: String)(implicit ec: ExecutionContext, tenant: Tenant) = Future {
    accessTokenStore.find(t => t._1 == value).map(_._2)
  }
  override def getRefreshToken(value: String)(implicit ec: ExecutionContext, tenant: Tenant) = Future {
    refreshTokenStore.find(t => t._1 == value).map(_._2)
  }
  override def markForRemoval(item: Expirable, key: Option[String])(implicit ec: ExecutionContext, tenant: Tenant) = Future {
    item match {
      case ar: AuthzRequest => key.foreach(authzCodeStore.remove(_))
      case at: AccessToken => accessTokenStore.remove(at.value)
      case rt: RefreshToken => refreshTokenStore.remove(rt.value)
      case _ => throw new IllegalArgumentException(s"Eviction not supported for item '$item'")
    }
  }
}

private object DefaultInMemoryStoreDelegate extends InMemoryStoreDelegate

class InMemoryOauth2Store extends Oauth2Store {
  import TenantImplicits.DefaultTenant
  lazy val delegate: Oauth2Store = DefaultInMemoryStoreDelegate
  override def storeClient(client: Oauth2Client)(implicit ec: ExecutionContext, tenant: Tenant) = delegate.storeClient(client)
  override def getClient(clientId: String)(implicit ec: ExecutionContext, tenant: Tenant) = delegate.getClient(clientId)
  override def storeAuthzRequest(
    authzCode: String,
    authzRequest: AuthzRequest)(implicit ec: ExecutionContext, tenant: Tenant) = delegate.storeAuthzRequest(authzCode, authzRequest)
  override def getAuthzRequest(authzCode: String)(implicit ec: ExecutionContext, tenant: Tenant) = delegate.getAuthzRequest(authzCode)
  override def storeTokens(
    accessAndRefreshTokens: AccessAndRefreshTokens,
    oauthClient: Oauth2Client)(implicit ec: ExecutionContext, tenant: Tenant) = delegate.storeTokens(accessAndRefreshTokens, oauthClient)
  override def getAccessToken(value: String)(implicit ec: ExecutionContext, tenant: Tenant) = delegate.getAccessToken(value)
  override def getRefreshToken(value: String)(implicit ec: ExecutionContext, tenant: Tenant) = delegate.getRefreshToken(value)
  override def markForRemoval(
    item: Expirable,
    key: Option[String])(implicit ec: ExecutionContext, tenant: Tenant) = delegate.markForRemoval(item, key)
}
