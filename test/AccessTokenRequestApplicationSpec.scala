package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import controllers.utils.AccessTokenErrors._
import controllers.client._
import controllers.utils.Req._
import controllers.utils.GrantTypes._
import controllers.Application
import org.apache.commons.codec.binary.Base64

@RunWith(classOf[JUnitRunner])
class AccessTokenRequestApplicationSpec extends Specification {

  "Application" should {

    s"send 401 if unregistered client" in new WithApplication {
      val resp = route(FakeClientRequestWoRegisteredClient(POST, "/oauth/token")).get
      //println(contentAsString(resp))
      status(resp) must equalTo(401)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_client))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString("unregistered client"))
    }

    s"send 401 if bad client credentials" in new WithApplication {
      Application.saveClient(OauthClient("the_client", Application.encodePassword("wrongpass"), Seq("global"), Seq(authorization_code), "http://www.host.com/cb", Seq(), 3600, 3600, None, false))
      val resp = route(FakeClientRequestWoRegisteredClient(POST, "/oauth/token")).get
      println(contentAsString(resp))
      status(resp) must equalTo(401)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_client))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString("bad credentials"))
    }

    s"send 400 if '$code' param is missing" in new WithApplication {
      val resp = route(FakeClientRequest(POST, "/oauth/token")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $code"))
    }

    s"send 400 if '$grant_type' param is missing" in new WithApplication {
      val resp = route(FakeClientRequest(POST, "/oauth/token")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $code"))
    }
  }

  private def FakeClientRequest(method: String, path: String) = {
    val pass = Application.encodePassword("pass")
    Application.saveClient(OauthClient("the_client", pass, Seq("global"), Seq(authorization_code), "http://www.host.com/cb", Seq(), 3600, 3600, None, false))
    FakeRequest(method, path).withHeaders("Authorization" -> ("Basic " + Base64.encodeBase64String("the_client:pass".getBytes)))
  }

  private def FakeClientRequestWoRegisteredClient(method: String, path: String) = {
    val pass = Application.encodePassword("pass")
    FakeRequest(method, path).withHeaders("Authorization" -> ("Basic " + Base64.encodeBase64String("the_client:pass".getBytes)))
  }
}
