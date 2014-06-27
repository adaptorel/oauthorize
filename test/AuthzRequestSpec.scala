package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import controllers.utils.Req._
import controllers.utils.AuthzErrors._
import controllers.utils.Error._
import controllers.utils.ResponseType._
import controllers.AuthzRequest
import play.api.libs.json.Json
import play.api.libs.json.JsString

@RunWith(classOf[JUnitRunner])
class AuthzRequestSpec extends Specification {
  
  "An Authorization request should" should {

    s"contain a valid $client_id request param" in {
      AuthzRequest(null, null, None, None, Seq()).getError.map(_ \ error) must beSome(JsString(invalid_request))
      AuthzRequest(null, null, None, None, Seq()).getError.map(_ \ error_description) must beSome(JsString(s"mandatory: $client_id"))
      AuthzRequest("a", "code", None, None, Seq()).getError must beNone
    }
    
    s"contain a valid $response_type request param" in {
      AuthzRequest("a", null, None, None, Seq()).getError.map(_ \ error) must beSome(JsString(invalid_request))
      AuthzRequest("a", null, None, None, Seq()).getError.map(_ \ error_description) must beSome(JsString(s"mandatory: $response_type"))
      AuthzRequest("a", "token", None, None, Seq()).getError must beNone
    }
    
    s"contain a $response_type of type $code or $token" in {
      AuthzRequest("a", "b", None, None, Seq()).getError.map(_ \ error) must beSome(JsString(invalid_request))
      AuthzRequest("a", "b", None, None, Seq()).getError.map(_ \ error_description) must beSome(JsString(s"mandatory: $response_type in ['$code','$token']"))
    }
    
  }
}
