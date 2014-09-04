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

@RunWith(classOf[JUnitRunner])
class RefreshTokenRequestApplicationSpec extends PlaySpecification with TestHelpers {

  "Application" should {

    s"send 400 if '$refresh_token' param is missing" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> GrantTypes.refresh_token)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $refresh_token"))
    }

    s"send 401 if unregistered client" in new WithServer(port = 3333) {
      val resp = postfWoRegisteredClient("/oauth/token", grant_type -> GrantTypes.refresh_token, refresh_token -> "whatever")
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("unregistered client"))
    }

    s"send 401 if bad client credentials" in new WithServer(port = 3333) {
      val client = Some(Oauth2Client("the_client", Oauth.hashClientSecret(SecretInfo("wrongpass")), Seq("global"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), RedirectUri, Seq(), 3600, 3600, None, false))
      val resp = postf("/oauth/token", grant_type -> GrantTypes.refresh_token, refresh_token -> "whatever")(client)
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("bad credentials"))
    }
    
    "respond with 400 if refresh_token unsupported" in new WithServer(port = 3333) {
      import oauth2.spec.AccessTokenResponseParams._
      val c = Oauth.storeClient(Oauth2Client("the_client", hash("pass"),
        Seq("global"), Seq(GrantTypes.authorization_code),
        RedirectUri, Seq(), 3600, 3600, None, true))
      val user = UserId("dorel@eloquentix.com", Some("google"))
      val resp = postf("/oauth/token", refresh_token -> "1123", grant_type -> GrantTypes.refresh_token)(Some(c))
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(unsupported_grant_type))
      (resp.json \ "error_description") must equalTo(JsString("unsupported grant type"))
    }

    "respond with 200 and the access token if request is correct" in new WithServer(port = 3333) {
      import oauth2.spec.AccessTokenResponseParams._
      val oauthClient = Oauth.storeClient(Oauth2Client("the_client", SecretInfo("pass"), Seq("global"), Seq(GrantTypes.authorization_code, refresh_token), RedirectUri, Seq(), 3600, 3600, None, true))
      val user = UserId("dorel@eloquentix.com", Some("google"))
      val accToken = Oauth.generateAccessToken(oauthClient, Seq("internal"), Some(user))
      val refToken = Oauth.generateRefreshToken(oauthClient, Seq("internal"), Some(user))
      Oauth.storeTokens(AccessAndRefreshTokens(accToken, Some(refToken)), oauthClient)
      val accessResp = postf1("/oauth/token", refresh_token -> refToken.value, grant_type -> GrantTypes.refresh_token)
      accessResp.status must equalTo(200)
      (accessResp.json \ access_token).as[String] must beMatching(".{53}")
      (accessResp.json \ token_type).as[String] must equalTo("bearer")
      (accessResp.json \ scope).as[String] must equalTo("internal")
      (accessResp.json \ expires_in).as[Int] must beGreaterThan(0)
    }
  }
}
