package oauthorize.test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import oauth2.spec.ResponseType
import oauth2.spec.Req._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Error._
import oauthorize.model._

@RunWith(classOf[JUnitRunner])
class AuthzRequestSpec extends Specification {

  "An Authorization request should" should {

    val Redir = "http://www.r.com/cb"
    val CorrectScope = Seq("internal")
    implicit val client = Oauth2Client("a", "a", CorrectScope, Seq("authorization_code"), Redir, Seq(), 3600, 3600, None, true)
    
    s"contain a valid $client_id request param" in {
      AuthzRequest(null, null, Redir, CorrectScope, true).getError.map(_.error) must beSome(invalid_request)
      AuthzRequest(null, null, Redir, CorrectScope, true).getError.map(_.error_description).get must beSome(s"mandatory: $client_id")
      AuthzRequest("a", ResponseType.code, Redir, CorrectScope, true).getError must beNone
    }

    s"contain a valid $response_type request param" in {
      AuthzRequest("a", null, Redir, CorrectScope, true).getError.map(_.error) must beSome(invalid_request)
      AuthzRequest("a", null, Redir, CorrectScope, true).getError.map(_.error_description).get must beSome(s"mandatory: $response_type")
      AuthzRequest("a", ResponseType.token, Redir, CorrectScope, true).getError must beNone
    }
    
    s"contain a valid redirect_uri request param" in {
      AuthzRequest("a", ResponseType.token, null, CorrectScope, true).getError.map(_.error) must beSome(invalid_request)
      AuthzRequest("a", ResponseType.token, null, CorrectScope, true).getError.map(_.error_description).get must beSome(s"mandatory: $redirect_uri")
      AuthzRequest("a", ResponseType.token, Redir, CorrectScope, true).getError must beNone
    }
    
    s"contain a valid scope request param" in {
      AuthzRequest("a", ResponseType.code, Redir, Seq(), true).getError.map(_.error) must beSome(invalid_request)
      AuthzRequest("a", ResponseType.code, Redir, Seq(), true).getError.map(_.error_description).get must beSome(s"mandatory: $scope")
      AuthzRequest("a", ResponseType.code, Redir, CorrectScope, true).getError must beNone
    }    

    s"contain a $response_type of type '${ResponseType.code}' or '${ResponseType.token}'" in {
      AuthzRequest("a", "b", Redir, CorrectScope, true).getError.map(_.error) must beSome(invalid_request)
      AuthzRequest("a", "b", Redir, CorrectScope, true).getError.map(_.error_description).get must beSome(s"mandatory: $response_type in ['${ResponseType.code}','${ResponseType.token}']")
    }

  }
}
