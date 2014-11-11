package oauthorize.sample

import oauthorize.model._
import oauthorize.playapp.defaults._

object Oauth {
  def hashClientSecret(info: SecretInfo) = clientSecretHasher.hashSecret(info)
  def storeClient(c: Oauth2Client) = store.storeClient(c)
  def generateAccessToken(c: Oauth2Client, scope: Seq[String], u: Option[UserId]) =
    tokens.generateAccessToken(c, scope, u)
  def generateRefreshToken(c: Oauth2Client, scope: Seq[String], u: Option[UserId]) =
    tokens.generateRefreshToken(c, scope, u)
  def storeTokens(t: AccessAndRefreshTokens, c: Oauth2Client) =
    store.storeTokens(t, c)
  def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest) =
    store.storeAuthzRequest(authzCode, authzRequest)
  def getAuthzRequest(authzCode: String) = store.getAuthzRequest(authzCode)  
}