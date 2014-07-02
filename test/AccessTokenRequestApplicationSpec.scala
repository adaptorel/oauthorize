package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import oauth2.spec.AccessTokenErrors._
import oauthze.model._
import oauth2.spec.Req._
import oauth2.spec.GrantTypes._
import controllers.Application
import org.apache.commons.codec.binary.Base64
import java.net.URLDecoder
import java.net.URLEncoder

@RunWith(classOf[JUnitRunner])
class AccessTokenRequestApplicationSpec extends Specification {
  
  val RedirectUri = "http://www.host.com/cb"

  "Application" should {
    
    s"send 401 if unregistered client" in new WithApplication {
      val resp = route(FakeClientRequestWoRegisteredClient(POST, "/oauth/token")).get
      //println(contentAsString(resp))
      status(resp) must equalTo(401)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_client))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString("unregistered client"))
    }

    s"send 401 if bad client credentials" in new WithApplication {
      Application.saveClient(OauthClient("the_client", Application.encodePassword("wrongpass"), Seq("global"), Seq(authorization_code), RedirectUri, Seq(), 3600, 3600, None, false))
      val resp = route(FakeClientRequestWoRegisteredClient(POST, "/oauth/token")).get
      status(resp) must equalTo(401)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_client))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString("bad credentials"))
    }

    s"send 400 if '$code' param is missing" in new WithApplication {
      val resp = route(FakeClientRequest(POST, "/oauth/token")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $code, $redirect_uri"))
    }

    s"send 400 if '$grant_type' param is missing" in new WithApplication {
      val resp = route(FakeClientRequest(POST, "/oauth/token")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $code, $redirect_uri"))
    }
    
    "respond with 200 and the access token if request is correct" in new WithApplication {
      import oauth2.spec.AccessTokenResponse._
      val authzResp = route(FakeClientRequest(GET, s"/oauth/authorize?client_id=the_client&response_type=code&state=555&scope=global&redirect_uri=$RedirectUri")).get
      val P = """.*?code=(.*)&state=555""".r
      val P(authzCode) = headers(authzResp).get("Location").get
      val accessResp = route(FakeClientRequest(POST, "/oauth/token").withFormUrlEncodedBody(code -> URLDecoder.decode(authzCode, "utf8"), grant_type -> authorization_code, redirect_uri -> RedirectUri)).get
      status(accessResp) must equalTo(200)
      (contentAsJson(accessResp) \ access_token).as[String] must beMatching(".{53}")
      (contentAsJson(accessResp) \ refresh_token).as[String] must beMatching(".{53}")
      (contentAsJson(accessResp) \ token_type).as[String] must equalTo("bearer")
      (contentAsJson(accessResp) \ expires_in).as[Int] must beGreaterThan(0)
    }
  }

  private def FakeClientRequest(method: String, path: String) = {
    val pass = Application.encodePassword("pass")
    Application.saveClient(OauthClient("the_client", pass, Seq("global"), Seq(authorization_code, refresh_token), RedirectUri, Seq(), 3600, 3600, None, true))
    FakeRequest(method, path).withHeaders("Authorization" -> ("Basic " + Base64.encodeBase64String("the_client:pass".getBytes)))
  }

  private def FakeClientRequestWoRegisteredClient(method: String, path: String) = {
    val pass = Application.encodePassword("pass")
    FakeRequest(method, path).withHeaders("Authorization" -> ("Basic " + Base64.encodeBase64String("the_client:pass".getBytes)))
  }
}
