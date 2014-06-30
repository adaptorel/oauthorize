package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import oauth.spec.ResponseType
import oauth.spec.Req._
import oauth.spec.AuthzErrors._
import oauth.spec.Error._
import oauthze.model._
import play.api.libs.json.Json
import play.api.libs.json.JsString

@RunWith(classOf[JUnitRunner])
class AuthzRequestSpec extends Specification {

  "An Authorization request should" should {

    s"contain a valid $client_id request param" in {
      AuthzRequest(null, null, None, None, Seq(), true).getError.map(_ \ error) must beSome(JsString(invalid_request))
      AuthzRequest(null, null, None, None, Seq(), true).getError.map(_ \ error_description) must beSome(JsString(s"mandatory: $client_id"))
      AuthzRequest("a", "code", None, None, Seq(), true).getError must beNone
    }

    s"contain a valid $response_type request param" in {
      AuthzRequest("a", null, None, None, Seq(), true).getError.map(_ \ error) must beSome(JsString(invalid_request))
      AuthzRequest("a", null, None, None, Seq(), true).getError.map(_ \ error_description) must beSome(JsString(s"mandatory: $response_type"))
      AuthzRequest("a", "token", None, None, Seq(), true).getError must beNone
    }

    s"contain a $response_type of type '${ResponseType.code}' or '${ResponseType.token}'" in {
      AuthzRequest("a", "b", None, None, Seq(), true).getError.map(_ \ error) must beSome(JsString(invalid_request))
      AuthzRequest("a", "b", None, None, Seq(), true).getError.map(_ \ error_description) must beSome(JsString(s"mandatory: $response_type in ['${ResponseType.code}','${ResponseType.token}']"))
    }

  }
}
