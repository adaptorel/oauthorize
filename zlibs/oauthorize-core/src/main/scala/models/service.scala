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

trait Oauth2Store {
  def storeClient(client: Oauth2Client): Oauth2Client
  def getClient(clientId: String): Option[Oauth2Client]
  def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest): AuthzRequest
  def getAuthzRequest(authzCode: String): Option[AuthzRequest]
  def storeTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client): AccessAndRefreshTokens
  def getAccessToken(value: String): Option[AccessToken]
  def getRefreshToken(value: String): Option[RefreshToken]
}

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

sealed trait Sha256SecretHasher {
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

sealed trait BCryptSecretHasher {
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

private object InMemoryStoreDelegate extends Oauth2Store {
  private val oauthClientStore = scala.collection.mutable.Map[String, Oauth2Client]()
  private val authzCodeStore = scala.collection.mutable.Map[String, AuthzRequest]()
  private val implicitTokenStore = scala.collection.mutable.Map[String, AccessToken]()
  private val accessTokenStore = scala.collection.mutable.Map[String, AccessAndRefreshTokens]()

  override def storeClient(client: Oauth2Client) = { oauthClientStore.put(client.clientId, client); client }
  override def getClient(clientId: String) = oauthClientStore.get(clientId)
  override def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest) = { authzCodeStore.put(authzCode, authzRequest); authzRequest }
  override def getAuthzRequest(authzCode: String) = authzCodeStore.get(authzCode)
  override def storeTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client) = { accessTokenStore.put(oauthClient.clientId, accessAndRefreshTokens); accessAndRefreshTokens }
  override def getAccessToken(value: String) = accessTokenStore.values.find(x => x.accessToken.value == value).map(_.accessToken)
  override def getRefreshToken(value: String) = accessTokenStore.values.find(x => x.refreshToken.exists(_.value == value)).flatMap(_.refreshToken)
}

trait InMemoryOauth2Store extends Oauth2Store {
  override def storeClient(client: Oauth2Client) = InMemoryStoreDelegate.storeClient(client)
  override def getClient(clientId: String) = InMemoryStoreDelegate.getClient(clientId)
  override def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest) = InMemoryStoreDelegate.storeAuthzRequest(authzCode, authzRequest)
  override def getAuthzRequest(authzCode: String) = InMemoryStoreDelegate.getAuthzRequest(authzCode)
  override def storeTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client) = InMemoryStoreDelegate.storeTokens(accessAndRefreshTokens, oauthClient)
  override def getAccessToken(value: String) = InMemoryStoreDelegate.getAccessToken(value)
  override def getRefreshToken(value: String) = InMemoryStoreDelegate.getRefreshToken(value)
}