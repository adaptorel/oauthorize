package oauthorize.sample

import oauthorize.model._
import oauthorize.playapp.defaults._
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Await
import scala.concurrent.duration._

object Oauth {

  val WaitTime = 5 seconds

  def hashClientSecret(info: SecretInfo) = clientSecretHasher.hashSecret(info)
  def storeClient(c: Oauth2Client) = Await.result(store.storeClient(c), WaitTime)
  def generateAccessToken(c: Oauth2Client, scope: Seq[String], u: Option[UserId]) =
    tokens.generateAccessToken(c, scope, u)
  def generateRefreshToken(c: Oauth2Client, scope: Seq[String], u: Option[UserId]) =
    tokens.generateRefreshToken(c, scope, u)
  def storeTokens(t: AccessAndRefreshTokens, c: Oauth2Client) =
    Await.result(store.storeTokens(t, c), WaitTime)
  def storeAuthzRequest(authzCode: String, authzRequest: AuthzRequest) =
    Await.result(store.storeAuthzRequest(authzCode, authzRequest), WaitTime)
  def getAuthzRequest(authzCode: String) =
    Await.result(store.getAuthzRequest(authzCode), WaitTime)
}