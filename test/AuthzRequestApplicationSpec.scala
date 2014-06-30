package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._

import play.api.test._
import play.api.test.Helpers._

import play.api.libs.json._
import controllers.utils.AuthzErrors._
import controllers.client._

@RunWith(classOf[JUnitRunner])
class AuthzRequestApplicationSpec extends Specification {

  "Application" should {

    "send 400 if client_id is missing" in new WithApplication {
      val resp = route(FakeRequest(GET, "/oauth/authorize")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
    }

    "send 400 if response_type is missing" in new WithApplication {
      val resp = route(FakeRequest(GET, "/oauth/authorize?client_id=a")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
    }

    "send 400 if response_type is wrong" in new WithApplication {
      val resp = route(FakeRequest(GET, "/oauth/authorize?client_id=a&response_type=eww")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
    }

    "send 302 if response_type is correct" in new WithApplication {
      val client = OauthClient("a", "a", Seq(), Seq("authorization_code"), "http://www.r.com/cb", Seq(), 3600, 3600, None, true)
      controllers.Application.saveClient(client)
      val resp = route(FakeRequest(GET, "/oauth/authorize?client_id=a&response_type=code&state=555")).get
      //println(contentAsString(resp))
      status(resp) must equalTo(302)
      headers(resp).get("Location").get must beMatching(".*code=\\w+.*")
      headers(resp).get("Location").get must beMatching(".*state=555.*")
    }
  }
}
