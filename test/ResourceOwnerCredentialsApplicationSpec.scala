package oauthorize.test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import oauth2.spec.AccessTokenErrors._
import oauth2.spec.Req._
import oauth2.spec.GrantTypes
import oauthorize.model._
import oauthorize.playapp.Oauth
import org.apache.commons.codec.binary.Base64
import java.net.URLDecoder
import java.net.URLEncoder
import play.api.Play
import play.api.libs.ws.WS
import com.ning.http.client.Realm
import play.api.libs.ws.WS.WSRequestHolder
import play.api.libs.ws.Response
import play.api.libs.ws.Response
import securesocial.core.UserService

@RunWith(classOf[JUnitRunner])
class ResourceOwnerCredentialsApplicationSpec extends PlaySpecification with TestHelpers {

  "Application" should {
    s"send 400 if '$username' '$password' params are missing" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> GrantTypes.password)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $username, $password, $scope"))
    }

    s"send 400 if '$password' param is missing" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> GrantTypes.password, username -> "user")
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $username, $password, $scope"))
    }

    s"send 400 if '$username' param is missing" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> GrantTypes.password, password -> "pass")
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $username, $password, $scope"))
    }

    s"send 400 if '$scope' param is missing" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> GrantTypes.password, username-> "user", password -> "pass")
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $username, $password, $scope"))
    }
    
    s"send 401 if unregistered client" in new WithServer(port = 3333) {
      val resp = postfWoRegisteredClient("/oauth/token", grant_type -> GrantTypes.password, username -> "whatever", password -> "whatever")
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("unregistered client"))
    }

    s"send 401 if bad client credentials" in new WithServer(port = 3333) {
      val client = Some(Oauth2Client("the_client", Oauth.hashClientSecret(SecretInfo("wrongpass")), Seq("global"), Seq(GrantTypes.password), RedirectUri, Seq(), 3600, 3600, None, false))
      val resp = postf("/oauth/token", grant_type -> GrantTypes.password, username -> "whatever", password -> "whatever", scope -> "global")(client)
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("bad credentials"))
    }

    s"send 400 if $password grant type is not supported" in new WithServer(port = 3333) {
      val client = Some(Oauth2Client("the_client", Oauth.hashClientSecret(SecretInfo("pass")), Seq("global"), Seq(GrantTypes.authorization_code), RedirectUri, Seq(), 3600, 3600, None, false))
      val resp = postf("/oauth/token", grant_type -> GrantTypes.password, username -> "a", "password" -> "a", scope -> "global")(client)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(unsupported_grant_type))
      (resp.json \ "error_description") must equalTo(JsString("unsupported grant type"))
    }
    
    s"send 400 if incorrect scope" in new WithServer(port = 3333) {
      import oauthorize.playapp.SecureTenantImplicits._
      val client = Some(Oauth2Client("the_client", Oauth.hashClientSecret(SecretInfo("pass")), Seq("global"), Seq(GrantTypes.password, GrantTypes.refresh_token), RedirectUri, Seq(), 3600, 3600, None, false))
      UserService.save(TestUser)
      val resp = postf("/oauth/token", grant_type -> GrantTypes.password, username -> "user@test.com", password -> "pass", "scope" -> "badscope")(client)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_scope))
      (resp.json \ "error_description") must equalTo(JsString("unsupported scope"))
    }    

    s"send 400 if resource_owner_credentials unsupported" in new WithServer(port = 3333) {
      import oauth2.spec.AccessTokenResponseParams._
      val client = Some(Oauth2Client("the_client", Oauth.hashClientSecret(SecretInfo("pass")), Seq("global"), Seq(GrantTypes.implic1t), RedirectUri, Seq(), 3600, 3600, None, false))
      UserService.save(TestUser)
      val accessResp = postf("/oauth/token", grant_type -> GrantTypes.password, username -> "user@test.com", password -> "pass", "scope" -> "global")(client)
      accessResp.status must equalTo(400)
      (accessResp.json \ "error") must equalTo(JsString(unsupported_grant_type))
      (accessResp.json \ "error_description") must equalTo(JsString("unsupported grant type"))
    }    
    
    s"send 200 if request is correct" in new WithServer(port = 3333) {
      import oauthorize.playapp.SecureTenantImplicits._
      import oauth2.spec.AccessTokenResponseParams._
      val client = Some(Oauth2Client("the_client", Oauth.hashClientSecret(SecretInfo("pass")), Seq("global"), Seq(GrantTypes.password, GrantTypes.refresh_token), RedirectUri, Seq(), 3600, 3600, None, false))
      UserService.save(TestUser)
      val accessResp = postf("/oauth/token", grant_type -> GrantTypes.password, username -> "user@test.com", password -> "pass", "scope" -> "global")(client)
      accessResp.status must equalTo(200)
      (accessResp.json \ access_token).as[String] must beMatching(".{53}")
      (accessResp.json \ refresh_token).as[String] must beMatching(".{53}")
      (accessResp.json \ token_type).as[String] must equalTo("bearer")
      (accessResp.json \ scope).as[String] must equalTo("global")
      (accessResp.json \ expires_in).as[Int] must beGreaterThan(0)
    }

  }
}
