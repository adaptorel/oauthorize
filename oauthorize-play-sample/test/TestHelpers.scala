package oauthorize.test

import java.net.URLEncoder
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import play.api.libs.ws.WS
import oauthorize.sample.Oauth
import oauthorize.model.Oauth2Client
import oauthorize.model.SecretInfo
import oauth2.spec.GrantTypes
import com.ning.http.client.Realm
import play.api.libs.ws.Response
import securesocial.core._
import play.api.mvc._

trait TestHelpers {

  val port = 3333
  val RedirectUri = s"http://localhost:$port/fake/cb"
  val TestUri = s"http://localhost:$port"

  def postWoRegisteredClient(url: String, content: (String, String)*) = {
    postfWoRegisteredClient(url, content: _*)
  }

  def postfWoRegisteredClient(url: String, content: (String, String)*) = {
    val urlEncoded = content.map(pair => URLEncoder.encode(pair._1, "utf-8") + "=" + URLEncoder.encode(pair._2, "utf-8")).mkString("&")
    await(WS.url(s"$TestUri$url").withAuth("no_client", "pass", Realm.AuthScheme.BASIC).withHeaders("Content-Type" -> "application/x-www-form-urlencoded; charset=utf-8").post(urlEncoded))
  }
  
  def postfWoBasicAuth(url: String, content: (String, String)*) = {
    val urlEncoded = content.map(pair => URLEncoder.encode(pair._1, "utf-8") + "=" + URLEncoder.encode(pair._2, "utf-8")).mkString("&")
    await(WS.url(s"$TestUri$url").withHeaders("Content-Type" -> "application/x-www-form-urlencoded").post(urlEncoded))
  }

  def post(url: String): Response = postf(url)(None)

  def postf1(url: String, content: (String, String)*): Response = postf(url, content: _*)(None)

  def postf(url: String, content: (String, String)*)(client: Option[Oauth2Client] = None): Response = {
    val urlEncoded = content.map(pair => URLEncoder.encode(pair._1, "utf-8") + "=" + URLEncoder.encode(pair._2, "utf-8")).mkString("&")
    Oauth.storeClient(client.getOrElse(Oauth2Client("the_client", hash("pass"), Seq("global"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), RedirectUri, Seq(), 3600, 3600, None, true)))
    await(WS.url(s"$TestUri$url").withAuth("the_client", "pass", Realm.AuthScheme.BASIC).withHeaders("Content-Type" -> "application/x-www-form-urlencoded; charset=utf-8").post(urlEncoded))
  }
  
  def hash(pass: String) = Oauth.hashClientSecret(SecretInfo(pass))
  
  def authenticatedCookie = Authenticator.create(TestUser).fold(z => throw new RuntimeException, c => Cookies.encode(Seq(c.toCookie)))
  
  def FakeLoginApp = FakeApplication(
      withoutPlugins = Seq("securesocial.core.DefaultAuthenticatorStore"),
      additionalPlugins = Seq("oauthorize.test.FakeLoggedInUserAuthenticatorStore"))
  
  lazy val TestUser = {
    val u = securesocial.core.SocialUser(
    IdentityId("user@test.com", "userpass"),
    "Test",
    "User",
    "Test User",
    Some("user@test.com"),
    None,
    AuthenticationMethod.UserPassword,
    None,
    None,
    Some(Registry.hashers.get("bcrypt").get.hash("pass")))
    UserService.save(u)
    u
  }
}

import play.api.Application
/*
 * We replace the authentication store with this one which will
 * provide TestUser as authenticated, you only need to have a
 * Authenticator.cookieName cookie in your request! Use the 
 * authenticatedCookie method above
 * 
 * Also remember it'll always return TestUser as the logged in user!
 */
class FakeLoggedInUserAuthenticatorStore(app: Application) extends AuthenticatorStore(app) with TestHelpers {
  def save(authenticator: Authenticator): Either[Error, Unit] = {
    Right(())
  }
  def find(id: String): Either[Error, Option[Authenticator]] = {
    val x = Authenticator.create(TestUser).fold(z => None, Some(_))
    Right(x)
  }
  def delete(id: String): Either[Error, Unit] = {
    Right(())
  }
}