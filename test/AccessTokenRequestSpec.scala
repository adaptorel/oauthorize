package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import oauth2.spec.Req._
import oauthze.utils._
import oauthze.model._
import oauth2.spec.GrantTypes._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec.Error._

import play.api.libs.json.Json
import play.api.libs.json.JsString

@RunWith(classOf[JUnitRunner])
class AccessTokenRequestSpec extends Specification {

  /*
   * Since we don't have the generated code for the AuthzRequest in this test case,
   * the authorization code value verification needs to be done in an integration test
   */

  //TODO Should we enforce a scope?

  "An Access token request should" should {

    s"compare the code $client_id and authenticatedClientId" in {
      val authzRequest = AuthzRequest("other_client", null, None, None, Seq(), true)
      AccessTokenRequest(null, "a", None, None).getError(authzRequest, "the_client").map(_ \ error) must beSome(JsString(invalid_grant))
      AccessTokenRequest(null, "a", None, None).getError(authzRequest, "the_client").map(_ \ error_description) must beSome(JsString(s"mismatched $client_id"))
    }

    s"contain a valid '$code' request param" in {
      val authzRequest = AuthzRequest("the_client", null, None, None, Seq(), true)
      AccessTokenRequest(authorization_code, null, None, None).getError(authzRequest, "the_client").map(_ \ error) must beSome(JsString(invalid_request))
      AccessTokenRequest(authorization_code, null, None, None).getError(authzRequest, "the_client").map(_ \ error_description) must beSome(JsString(s"mandatory: $code"))
      AccessTokenRequest(authorization_code, " ", None, None).getError(authzRequest, "the_client").map(_ \ error) must beSome(JsString(invalid_request))
      AccessTokenRequest(authorization_code, " ", None, None).getError(authzRequest, "the_client").map(_ \ error_description) must beSome(JsString(s"mandatory: $code"))
    }
    
    s"contain a valid '$grant_type' request param" in {
      val authzRequest = AuthzRequest("the_client", null, None, None, Seq(), true)
      AccessTokenRequest(null, "a", None, None).getError(authzRequest, "the_client").map(_ \ error) must beSome(JsString(invalid_request))
      AccessTokenRequest(null, "a", None, None).getError(authzRequest, "the_client").map(_ \ error_description) must beSome(JsString(s"mandatory: $grant_type"))
      AccessTokenRequest(" ", "a", None, None).getError(authzRequest, "the_client").map(_ \ error) must beSome(JsString(invalid_request))
      AccessTokenRequest(" ", "a", None, None).getError(authzRequest, "the_client").map(_ \ error_description) must beSome(JsString(s"mandatory: $grant_type"))
    }

    s"contain a '$grant_type' of precisely '$authorization_code'" in {
      val authzRequest = AuthzRequest("the_client", null, None, None, Seq(), true)
      AccessTokenRequest("wrong_grant_type", "a", None, None).getError(authzRequest, "the_client").map(_ \ error) must beSome(JsString(invalid_grant))
      AccessTokenRequest("wrong_grant_type", "a", None, None).getError(authzRequest, "the_client").map(_ \ error_description) must beSome(JsString(s"mandatory: $grant_type in ['$authorization_code']"))
    }

    s"ensure redirect_uri present in both if in authz request, and equal" in {
      val authzRequest = AuthzRequest("the_client", null, None, Some("htttp://host.com/cb"), Seq(), true)
      AccessTokenRequest(authorization_code, "the_code", None, None).getError(authzRequest, "the_client").map(_ \ error) must beSome(JsString(invalid_request))
      AccessTokenRequest("authorization_code", "the_code", None, None).getError(authzRequest, "the_client").map(_ \ error_description) must beSome(JsString(s"mismatched: $redirect_uri"))
    }
  }
}
