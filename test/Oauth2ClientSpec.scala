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
class Oauth2ClientSpec extends Specification {

  val client = Oauth2Client("the_client", SecretInfo(""), Seq("read", "write"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), "", Seq(), 3600, 3600, None, true)

  "An Access token request should" should {

    "fail if given scopes do not match" in {
      client.invalidScopes(Some("whatever")) must beTrue
      client.invalidScopes(Seq("whatever")) must beTrue
    }

    "fail if given scopes do not match" in {
      client.invalidScopes(Some("read fake")) must beTrue
      client.invalidScopes(Seq("read", "fake")) must beTrue
    }

    "fail if empty string" in {
      client.invalidScopes(Some("")) must beTrue
      client.invalidScopes(Seq("")) must beTrue
    }

    "let it pass if empty scopes. spec allows empty scope" in {
      client.invalidScopes(None) must beFalse
      client.invalidScopes(Seq()) must beFalse
    }

    "let it pass if one correct" in {
      client.invalidScopes(Some("read")) must beFalse
      client.invalidScopes(Seq("read")) must beFalse
    }

    "let it pass if one correct" in {
      val client2 = Oauth2Client("the_client", SecretInfo(""), Seq("read"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), "", Seq(), 3600, 3600, None, true)
      client2.invalidScopes(Some("read")) must beFalse
      client2.invalidScopes(Seq("read")) must beFalse
    }

    "let it pass if all correct" in {
      client.invalidScopes(Some("read write")) must beFalse
      client.invalidScopes(Seq("read", "write")) must beFalse
    }

    "let it pass if all correct order not important" in {
      client.invalidScopes(Some("write read")) must beFalse
      client.invalidScopes(Seq("write","read")) must beFalse
    }
  }
}
