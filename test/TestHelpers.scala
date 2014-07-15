package test

import java.net.URLEncoder
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import play.api.libs.ws.WS
import app.Oauth
import oauthorize.model.Oauth2Client
import oauth2.spec.GrantTypes
import com.ning.http.client.Realm
import play.api.libs.ws.Response
import securesocial.core._

trait TestHelpers {

  val RedirectUri = "http://www.host.com/cb"
  val port = 3333
  val TestUri = s"http://localhost:$port"

  def postWoRegisteredClient(url: String, content: (String, String)*) = {
    postfWoRegisteredClient(url, content: _*)
  }

  def postfWoRegisteredClient(url: String, content: (String, String)*) = {
    val urlEncoded = content.map(pair => URLEncoder.encode(pair._1, "utf-8") + "=" + URLEncoder.encode(pair._2, "utf-8")).mkString("&")
    await(WS.url(s"$TestUri$url").withAuth("no_client", "pass", Realm.AuthScheme.BASIC).withHeaders("Content-Type" -> "application/x-www-form-urlencoded").post(urlEncoded))
  }

  def post(url: String): Response = postf(url)(None)

  def postf1(url: String, content: (String, String)*): Response = postf(url, content: _*)(None)

  def postf(url: String, content: (String, String)*)(client: Option[Oauth2Client] = None): Response = {
    val urlEncoded = content.map(pair => URLEncoder.encode(pair._1, "utf-8") + "=" + URLEncoder.encode(pair._2, "utf-8")).mkString("&")
    val pass = Oauth.encodePassword("pass")
    Oauth.storeClient(client.getOrElse(Oauth2Client("the_client", pass, Seq("global"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), RedirectUri, Seq(), 3600, 3600, None, true)))
    await(WS.url(s"$TestUri$url").withAuth("the_client", "pass", Realm.AuthScheme.BASIC).withHeaders("Content-Type" -> "application/x-www-form-urlencoded").post(urlEncoded))
  }

  lazy val TestUser = securesocial.core.SocialUser(
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

}