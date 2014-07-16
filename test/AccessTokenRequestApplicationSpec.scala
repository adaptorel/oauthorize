package oauthorize.test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec.Req._
import oauth2.spec.GrantTypes
import oauthorize.model._
import org.apache.commons.codec.binary.Base64
import java.net.URLDecoder
import java.net.URLEncoder
import play.api.Play
import oauthorize.playapp.Oauth
import play.api.libs.ws._
import com.ning.http.client.Realm
import play.api.libs.ws.WS.WSRequestHolder

@RunWith(classOf[JUnitRunner])
class AccessTokenRequestApplicationSpec extends PlaySpecification with TestHelpers {

  "Application" should {

    s"send 401 if unregistered client" in new WithServer(port = 3333) {
      val resp = postfWoRegisteredClient("/oauth/token", grant_type -> GrantTypes.authorization_code, code -> "whatever", redirect_uri -> RedirectUri)
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("unregistered client"))
    }

    s"send 401 if bad client credentials" in new WithServer(port = 3333) {
      val client = Some(Oauth2Client("the_client", Oauth.encodePassword("wrongpass"), Seq("global"), Seq(GrantTypes.authorization_code), RedirectUri, Seq(), 3600, 3600, None, false))
      val resp = postf("/oauth/token", grant_type -> GrantTypes.authorization_code, code -> "whatever", redirect_uri -> RedirectUri)(client)
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("bad credentials"))
    }

    //TODO This fails now because we must fake a logged in user with SecureSocial for the approval to pass
    "respond with 200 and the access token if request is correct" in new WithServer(port = 3333) {
      import oauth2.spec.AccessTokenResponseParams._
      Oauth.storeClient(Oauth2Client("the_client", "pass", Seq("global"), Seq(GrantTypes.authorization_code, refresh_token), RedirectUri, Seq(), 3600, 3600, None, true))
      val authzResp = await(WS.url(s"$TestUri/oauth/authorize?client_id=the_client&response_type=code&state=555&scope=global&redirect_uri=$RedirectUri").get)
      val P = """.*?code=(.*)&state=555""".r
      val P(authzCode) = authzResp.header("Location").get
      val accessResp = postf1("/oauth/token", code -> URLDecoder.decode(authzCode, "utf8"), grant_type -> GrantTypes.authorization_code, redirect_uri -> RedirectUri)
      accessResp.status must equalTo(200)
      (accessResp.json \ access_token).as[String] must beMatching(".{53}")
      (accessResp.json \ refresh_token).as[String] must beMatching(".{53}")
      (accessResp.json \ token_type).as[String] must equalTo("bearer")
      (accessResp.json \ scope).as[String] must equalTo("global")
      (accessResp.json \ expires_in).as[Int] must beGreaterThan(0)
    }
  }
}
