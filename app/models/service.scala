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
  override def passwordMatches(rawPassword: String, encodedPassword: String): Boolean = BCrypt.checkpw(rawPassword, prefix + encodedPassword)
}

trait OauthClientStore {
  def saveClient(client: OauthClient): OauthClient
  def getClient(clientId: String): Option[OauthClient]
  def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: OauthClient)
  def getAuthzRequest(authzCode: String): Option[AuthzRequest]
  def storeImplicitToken(token: AccessToken, oauthClient: OauthClient): AccessToken
  def storeAccessAndRefreshTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: OauthClient): AccessAndRefreshTokens
  def getAuthDataForClient(clientId: String): Option[AccessAndRefreshTokens]
}

trait InMemoryOauthClientStore extends OauthClientStore {
  private val oauthClientStore = scala.collection.mutable.Map[String, OauthClient]()
  private val authzCodeStore = scala.collection.mutable.Map[String, AuthzRequest]()
  private val implicitTokenStore = scala.collection.mutable.Map[String, AccessToken]()
  private val accessTokenStore = scala.collection.mutable.Map[String, AccessAndRefreshTokens]()

  override def saveClient(client: OauthClient) = { oauthClientStore.put(client.clientId, client); client }
  override def getClient(clientId: String) = oauthClientStore.get(clientId)
  override def storeAuthzCode(authzCode: String, authzRequest: AuthzRequest, oauthClient: OauthClient) = { authzCodeStore.put(authzCode, authzRequest) }
  override def getAuthzRequest(authzCode: String) = authzCodeStore.get(authzCode)
  override def storeImplicitToken(token: AccessToken, oauthClient: OauthClient): AccessToken = { implicitTokenStore.put(token.value, token); token }
  override def storeAccessAndRefreshTokens(accessAndRefreshTokens: AccessAndRefreshTokens, oauthClient: OauthClient) = { accessTokenStore.put(oauthClient.clientId, accessAndRefreshTokens); accessAndRefreshTokens }
  override def getAuthDataForClient(clientId: String) = accessTokenStore.get(clientId)
}

trait AuthzCodeGenerator {
  def generateCode(authzRequest: AuthzRequest): String
  def generateAccessToken(authzRequest: AuthzRequest, oauthClient: OauthClient): AccessToken
  def generateRefreshToken(authzRequest: AuthzRequest, oauthClient: OauthClient): RefreshToken
}

trait DefaultAuthzCodeGenerator extends AuthzCodeGenerator {
  this: PasswordEncoder =>
  override def generateCode(authzRequest: AuthzRequest) = newToken
  //no refresh token for authorization request token / implicit grant
  override def generateAccessToken(authzRequest: AuthzRequest, oauthClient: OauthClient) = AccessToken(newToken, oauthClient.clientId, authzRequest.scope, oauthClient.accessTokenValidity, System.currentTimeMillis)
  override def generateRefreshToken(authzRequest: AuthzRequest, oauthClient: OauthClient) = RefreshToken(newToken, oauthClient.clientId, authzRequest.scope, oauthClient.accessTokenValidity, System.currentTimeMillis)
  def newToken = encodePassword(UUID.randomUUID().toString)
}