package oauthorize.test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import oauth2.spec.Req._
import oauthorize.utils._
import oauthorize.model._
import oauth2.spec.GrantTypes._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec.Error._
import oauth2.spec.ResponseType
import oauth2.spec.GrantTypes

@RunWith(classOf[JUnitRunner])
class AccessTokenRequestSpec extends Specification {

  /*
   * Since we don't have the generated code for the AuthzRequest in this test case,
   * the authorization code value verification needs to be done in an integration test
   */

  //TODO Should we enforce a scope?

  "An Access token request should" should {

    val RedirUri = "http://www.a.com/cb"
    val WrongRedirUri = "http://www.aaa.com/cb"
    val client = Oauth2Client("the_client", SecretInfo("pass"), Seq("global"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), RedirUri, Seq(), 3600, 3600, None, true)
    
    s"compare the code $client_id and authenticatedClientId" in {
      val authzRequest = AuthzRequest("other_client", null, RedirUri, Seq(), true)
      AccessTokenRequest(null, "a", RedirUri, None).getError(authzRequest, client).map(_.error) must beSome(invalid_grant)
      AccessTokenRequest(null, "a", RedirUri, None).getError(authzRequest, client).map(_.error_description).get must beSome(s"mismatched $client_id")
    }

    s"contain a valid '$code' request param" in {
      val authzRequest = AuthzRequest("the_client", null, RedirUri, Seq(), true)
      AccessTokenRequest(authorization_code, null, RedirUri, None).getError(authzRequest, client).map(_.error) must beSome(invalid_request)
      AccessTokenRequest(authorization_code, null, RedirUri, None).getError(authzRequest, client).map(_.error_description).get must beSome(s"mandatory: $code")
      AccessTokenRequest(authorization_code, " ", RedirUri, None).getError(authzRequest, client).map(_.error) must beSome(invalid_request)
      AccessTokenRequest(authorization_code, " ", RedirUri, None).getError(authzRequest, client).map(_.error_description).get must beSome(s"mandatory: $code")
    }
    
    s"contain a valid '$grant_type' request param" in {
      val authzRequest = AuthzRequest("the_client", null, RedirUri, Seq(), true)
      AccessTokenRequest(null, "a", RedirUri, None).getError(authzRequest, client).map(_.error) must beSome(invalid_request)
      AccessTokenRequest(null, "a", RedirUri, None).getError(authzRequest, client).map(_.error_description).get must beSome(s"mandatory: $grant_type")
      AccessTokenRequest(" ", "a", RedirUri, None).getError(authzRequest, client).map(_.error) must beSome(invalid_request)
      AccessTokenRequest(" ", "a", RedirUri, None).getError(authzRequest, client).map(_.error_description).get must beSome(s"mandatory: $grant_type")
    }

    s"contain a '$grant_type' of precisely '$authorization_code'" in {
      val authzRequest = AuthzRequest("the_client", null, RedirUri, Seq(), true)
      AccessTokenRequest("wrong_grant_type", "a", RedirUri, None).getError(authzRequest, client).map(_.error) must beSome(unsupported_grant_type)
      AccessTokenRequest("wrong_grant_type", "a", RedirUri, None).getError(authzRequest, client).map(_.error_description).get must beSome("unsupported grant type")
    }
    
    s"contain a valid '$redirect_uri'" in {
      val authzRequest = AuthzRequest("the_client", null, RedirUri, Seq(), true)
      AccessTokenRequest(authorization_code, "a", null, None).getError(authzRequest, client).map(_.error) must beSome(invalid_request)
      AccessTokenRequest(authorization_code, "a", null, None).getError(authzRequest, client).map(_.error_description).get must beSome(s"mandatory: $redirect_uri")
    }

    s"ensure redirect_uri present in both and equal" in {
      val authzRequest = AuthzRequest("the_client", ResponseType.code, RedirUri, Seq(), true)
      AccessTokenRequest(authorization_code, "the_code", WrongRedirUri, None).getError(authzRequest, client).map(_.error) must beSome(invalid_request)
      AccessTokenRequest("authorization_code", "the_code", WrongRedirUri, None).getError(authzRequest, client).map(_.error_description).get must beSome(s"mismatched: $redirect_uri")
    }
  }
}
