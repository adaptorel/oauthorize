package oauthorize.service

import oauthorize.utils._
import oauthorize.model._
import java.util.UUID
import bcrypt.BCrypt
import java.security.SecureRandom

trait PasswordEncoder {
  def encodePassword(pwd: String): String
  def passwordMatches(rawPassword: String, encodedPassword: String): Boolean
}

trait Sha256PasswordEncoder extends PasswordEncoder {
  override def encodePassword(pwd: String): String = sha256(pwd)
  override def passwordMatches(rawPassword: String, encodedPassword: String): Boolean = sha256(rawPassword) == encodedPassword
}

trait BCryptPasswordEncoder extends PasswordEncoder {
  private val rnd = new SecureRandom
  val rounds = 10
  private def paddedRounds = { rounds.toString.reverse.padTo(2, "0").reverse.mkString }
  private def prefix = "$2a$" + paddedRounds + "$"
  override def encodePassword(pwd: String): String = BCrypt.hashpw(pwd, BCrypt.gensalt(rounds, rnd)).substring(7)
  override def passwordMatches(rawPassword: String, encodedPassword: String): Boolean = {
    (for {
      raw <- Option(rawPassword)
      enc <- Option(encodedPassword)
    } yield {
      enc.length == (60 - prefix.length) && BCrypt.checkpw(rawPassword, prefix + encodedPassword)
    }) getOrElse (false)
  }
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
  override def getRefreshToken(value: String) = accessTokenStore.values.find(x => x.refreshToken.map(_.value == value).getOrElse(false)).flatMap(_.refreshToken)
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

trait AuthzCodeGenerator {
  def generateCode(authzRequest: AuthzRequest): String
  def generateAccessToken(oauthClient: Oauth2Client, scope: Seq[String], userId: Option[String] = None): AccessToken
  def generateRefreshToken(oauthClient: Oauth2Client, userId: Option[String] = None): RefreshToken
}

trait DefaultAuthzCodeGenerator extends AuthzCodeGenerator {
  this: PasswordEncoder =>
  override def generateCode(authzRequest: AuthzRequest) = newToken
  override def generateAccessToken(oauthClient: Oauth2Client, authScope: Seq[String], userId: Option[String] = None) = AccessToken(newToken, oauthClient.clientId, authScope, oauthClient.accessTokenValidity, System.currentTimeMillis, userId)
  override def generateRefreshToken(oauthClient: Oauth2Client, userId: Option[String] = None) = RefreshToken(newToken, oauthClient.clientId, oauthClient.refreshtokenValidity, System.currentTimeMillis, userId)
  def newToken = encodePassword(UUID.randomUUID().toString)
}

trait ExecutionContextProvider {
  import scala.concurrent.ExecutionContext
  implicit def oauthExecutionContext: ExecutionContext
}