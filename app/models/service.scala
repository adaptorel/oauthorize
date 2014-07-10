package oauthze.service

import oauthze.utils._
import oauthze.model._
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

trait OauthClientStore {
  def saveClient(client: Oauth2Client): Oauth2Client
  def getClient(clientId: String): Option[Oauth2Client]
  def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: Oauth2Client)
  def getAuthzRequest(authzCode: String): Option[AuthzRequest]
  def storeImplicitToken(token: AccessToken, oauthClient: Oauth2Client): AccessToken
  def storeAccessAndRefreshTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client): AccessAndRefreshTokens
  def getAuthDataForClient(clientId: String): Option[AccessAndRefreshTokens]
}

private object InMemoryStoreDelegate extends OauthClientStore {
  private val oauthClientStore = scala.collection.mutable.Map[String, Oauth2Client]()
  private val authzCodeStore = scala.collection.mutable.Map[String, AuthzRequest]()
  private val implicitTokenStore = scala.collection.mutable.Map[String, AccessToken]()
  private val accessTokenStore = scala.collection.mutable.Map[String, AccessAndRefreshTokens]()

  override def saveClient(client: Oauth2Client) = { oauthClientStore.put(client.clientId, client); client }
  override def getClient(clientId: String) = oauthClientStore.get(clientId)
  override def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: Oauth2Client) = { authzCodeStore.put(authzCode, authzRequest) }
  override def getAuthzRequest(authzCode: String) = authzCodeStore.get(authzCode)
  override def storeImplicitToken(token: AccessToken, oauthClient: Oauth2Client): AccessToken = { implicitTokenStore.put(token.value, token); token }
  override def storeAccessAndRefreshTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client) = { accessTokenStore.put(oauthClient.clientId, accessAndRefreshTokens); accessAndRefreshTokens }
  override def getAuthDataForClient(clientId: String) = accessTokenStore.get(clientId)
}

trait InMemoryOauthClientStore extends OauthClientStore {
  override def saveClient(client: Oauth2Client) = InMemoryStoreDelegate.saveClient(client)
  override def getClient(clientId: String) = InMemoryStoreDelegate.getClient(clientId)
  override def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: Oauth2Client) = InMemoryStoreDelegate.storeAuthzCode(authzCode, authzRequest, oauthClient)
  override def getAuthzRequest(authzCode: String) = InMemoryStoreDelegate.getAuthzRequest(authzCode)
  override def storeImplicitToken(token: AccessToken, oauthClient: Oauth2Client): AccessToken = InMemoryStoreDelegate.storeImplicitToken(token, oauthClient)
  override def storeAccessAndRefreshTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: Oauth2Client) = InMemoryStoreDelegate.storeAccessAndRefreshTokens(accessAndRefreshTokens, oauthClient)
  override def getAuthDataForClient(clientId: String) = InMemoryStoreDelegate.getAuthDataForClient(clientId)
}

trait AuthzCodeGenerator {
  def generateCode(authzRequest: AuthzRequest): String
  def generateAccessToken(oauthClient: Oauth2Client, scope: Seq[String]): AccessToken
  def generateRefreshToken(oauthClient: Oauth2Client): RefreshToken
}

trait DefaultAuthzCodeGenerator extends AuthzCodeGenerator {
  this: PasswordEncoder =>
  override def generateCode(authzRequest: AuthzRequest) = newToken
  override def generateAccessToken(oauthClient: Oauth2Client, authScope: Seq[String]) = AccessToken(newToken, oauthClient.clientId, authScope, oauthClient.accessTokenValidity, System.currentTimeMillis)
  override def generateRefreshToken(oauthClient: Oauth2Client) = RefreshToken(newToken, oauthClient.clientId, oauthClient.refreshtokenValidity, System.currentTimeMillis)
  def newToken = encodePassword(UUID.randomUUID().toString)
}