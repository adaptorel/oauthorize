package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthze.model._
import java.net.URLDecoder

@RunWith(classOf[JUnitRunner])
class AuthzRequestApplicationSpec extends Specification {

  val RedirectUri = "http://www.r.com/cb"
  
  "Application" should {

    "send 400 if client_id is missing" in new WithApplication {
      val resp = route(FakeRequest(GET, "/oauth/authorize")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }

    "send 400 if response_type is missing" in new WithApplication {
      val resp = route(FakeRequest(GET, "/oauth/authorize?client_id=a")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }

    "send 400 if response_type is wrong" in new WithApplication {
      val resp = route(FakeRequest(GET, "/oauth/authorize?client_id=a&response_type=eww")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }
    
    "send 400 if redirect_uri is wrong" in new WithApplication {
      val resp = route(FakeRequest(GET, "/oauth/authorize?client_id=a&response_type=code")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }
    
    "send 400 if redirect_uri is not matching client's" in new WithApplication {
      val client = OauthClient("a", "a", Seq("internal"), Seq("authorization_code"), RedirectUri, Seq(), 3600, 3600, None, true)
      controllers.Application.saveClient(client)
      val resp = route(FakeRequest(GET, "/oauth/authorize?client_id=a&response_type=code&scope=internal&redirect_uri=wrongredirect")).get
      status(resp) must equalTo(400)
      (contentAsJson(resp) \ "error") must equalTo(JsString(invalid_request))
      (contentAsJson(resp) \ "error_description") must equalTo(JsString(s"missmatched: $redirect_uri"))
    }

    "send 302 if response_type is correct" in new WithApplication {
      val client = OauthClient("a", "a", Seq("internal"), Seq("authorization_code"), RedirectUri, Seq(), 3600, 3600, None, true)
      controllers.Application.saveClient(client)
      val CodeParamRegex = """.*?code=(.*)&state=555""".r
      val resp = route(FakeRequest(GET, s"/oauth/authorize?client_id=a&response_type=code&state=555&redirect_uri=$RedirectUri&scope=internal")).get
      //println(contentAsString(resp))
      status(resp) must equalTo(302)
      val expectedUri = headers(resp).get("Location").get
      val CodeParamRegex(authzCode) = expectedUri
      URLDecoder.decode(authzCode, "utf-8") must beMatching(".{53}")
      expectedUri must beMatching(".*state=555.*")
    }
  }
}
