package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec.Req._
import oauth2.spec.GrantTypes._
import oauthze.model._
import org.apache.commons.codec.binary.Base64
import java.net.URLDecoder
import java.net.URLEncoder
import play.api.Play
import app.OauthMix
import app.Oauth
import play.api.libs.ws.WS
import com.ning.http.client.Realm
import play.api.libs.ws.WS.WSRequestHolder
import play.api.libs.ws.Response
import play.api.libs.ws.Response

@RunWith(classOf[JUnitRunner])
class AccessTokenRequestApplicationSpec extends PlaySpecification {

  val RedirectUri = "http://www.host.com/cb"
  val port = 3333
  val TestUri = s"http://localhost:$port"

  "Application" should {

    s"send 400 if not POST" in new WithServer(port = 3333) {
      val resp = await(WS.url(s"$TestUri/oauth/token").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString("mandatory: HTTPS POST"))
    }    
    
    s"send 400 if '$grant_type' param is missing" in new WithServer(port = 3333) {
      val resp = post("/oauth/token")
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString("invalid grant type"))
    }
    
    s"send 400 if '$grant_type' param is invalid" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> "whatever", code -> "whatever")
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString("invalid grant type"))
    }    

    s"send 400 if '$code' param is missing" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> authorization_code)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $code parameter"))
    }

    s"send 401 if unregistered client" in new WithServer(port = 3333) {
      val resp = postfWoRegisteredClient("/oauth/token", grant_type -> authorization_code, code -> "whatever", redirect_uri -> RedirectUri)
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("unregistered client"))
    }

    s"send 401 if bad client credentials" in new WithServer(port = 3333) {
      val client = Some(Oauth2Client("the_client", Oauth.encodePassword("wrongpass"), Seq("global"), Seq(authorization_code), RedirectUri, Seq(), 3600, 3600, None, false))
      val resp = postf("/oauth/token", grant_type -> authorization_code, code -> "whatever", redirect_uri -> RedirectUri)(client)
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("bad credentials"))
    }

    //TODO This fails now because we must fake a logged in user with SecureSocial for the approval to pass
    "respond with 200 and the access token if request is correct" in new WithServer(port = 3333) {
      import oauth2.spec.AccessTokenResponseParams._
      Oauth.storeClient(Oauth2Client("the_client", "pass", Seq("global"), Seq(authorization_code, refresh_token), RedirectUri, Seq(), 3600, 3600, None, true))
      val authzResp = await(WS.url(s"$TestUri/oauth/authorize?client_id=the_client&response_type=code&state=555&scope=global&redirect_uri=$RedirectUri").get)
      val P = """.*?code=(.*)&state=555""".r
      val P(authzCode) = authzResp.header("Location").get
      val accessResp = postf1("/oauth/token", code -> URLDecoder.decode(authzCode, "utf8"), grant_type -> authorization_code, redirect_uri -> RedirectUri)
      accessResp.status must equalTo(200)
      (accessResp.json \ access_token).as[String] must beMatching(".{53}")
      (accessResp.json \ refresh_token).as[String] must beMatching(".{53}")
      (accessResp.json \ token_type).as[String] must equalTo("bearer")
      (accessResp.json \ expires_in).as[Int] must beGreaterThan(0)
    }
  }

  private def postWoRegisteredClient(url: String, content: (String, String)*) = {
    postfWoRegisteredClient(url, content :_*)
  }

  private def postfWoRegisteredClient(url: String, content: (String, String) *) = {
    val urlEncoded = content.map(pair => URLEncoder.encode(pair._1, "utf-8") + "=" + URLEncoder.encode(pair._2, "utf-8")).mkString("&")
    await(WS.url(s"$TestUri$url").withAuth("no_client", "pass", Realm.AuthScheme.BASIC).withHeaders("Content-Type" -> "application/x-www-form-urlencoded").post(urlEncoded))
  }

  private def post(url: String): Response = postf(url)(None)
  
  private def postf1(url: String, content: (String, String)*): Response = postf(url, content :_*)(None)
  
  private def postf(url: String, content: (String, String)*)(client: Option[Oauth2Client] = None): Response = {
    val urlEncoded = content.map(pair => URLEncoder.encode(pair._1, "utf-8") + "=" + URLEncoder.encode(pair._2, "utf-8")).mkString("&")
    val pass = Oauth.encodePassword("pass")
    Oauth.storeClient(client.getOrElse(Oauth2Client("the_client", pass, Seq("global"), Seq(authorization_code, refresh_token), RedirectUri, Seq(), 3600, 3600, None, true)))
    await(WS.url(s"$TestUri$url").withAuth("the_client", "pass", Realm.AuthScheme.BASIC).withHeaders("Content-Type" -> "application/x-www-form-urlencoded").post(urlEncoded))
  }
}
