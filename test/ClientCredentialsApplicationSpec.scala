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
import org.apache.commons.codec.binary.Base64
import java.net.URLDecoder
import java.net.URLEncoder
import play.api.Play
import oauthorize.playapp.Oauth
import play.api.libs.ws._
import com.ning.http.client.Realm
import play.api.libs.ws.WS.WSRequestHolder

@RunWith(classOf[JUnitRunner])
class ClientCredentialsApplicationSpec extends PlaySpecification with TestHelpers {

  import oauthorize.service.TenantImplicits._
  
  "Application" should {

    s"send 401 if unregistered client" in new WithServer(port = 3333) {
      val resp = postfWoRegisteredClient("/oauth/token", grant_type -> GrantTypes.client_credentials)
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("unregistered client"))
    }

    s"send 401 if bad client credentials" in new WithServer(port = 3333) {
      val client = Some(Oauth2Client("the_client", Oauth.hashClientSecret(SecretInfo("wrongpass")), Seq("global"), Seq(GrantTypes.authorization_code), RedirectUri, Seq(), 3600, 3600, None, false))
      val resp = postf("/oauth/token", grant_type -> GrantTypes.client_credentials)(client)
      resp.status must equalTo(401)
      (resp.json \ "error") must equalTo(JsString(invalid_client))
      (resp.json \ "error_description") must equalTo(JsString("bad credentials"))
    }

    "respond with 400 if incorrect scope" in new WithServer(port = 3333) {
      import oauth2.spec.AccessTokenResponseParams._
      val c = Oauth.storeClient(Oauth2Client("the_client", hash("pass"),
        Seq("global"), Seq(GrantTypes.client_credentials, GrantTypes.refresh_token),
        RedirectUri, Seq(), 3600, 3600, None, true))
      val resp = postf("/oauth/token", grant_type -> GrantTypes.client_credentials, "scope" -> "nonexistent")(Some(c))
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_scope))
      (resp.json \ "error_description") must equalTo(JsString("unsupported scope"))
    }
    
    "respond with 200 and the access token if request is correct" in new WithServer(port = 3333) {
      import oauth2.spec.AccessTokenResponseParams._
      val c = Oauth.storeClient(Oauth2Client("the_client", hash("pass"),
        Seq("global"), Seq(GrantTypes.client_credentials, GrantTypes.refresh_token),
        RedirectUri, Seq(), 3600, 3600, None, true))
      val resp = postf("/oauth/token", grant_type -> GrantTypes.client_credentials, "scope" -> "global")(Some(c))
      resp.status must equalTo(200)
      (resp.json \ access_token).as[String] must beMatching(".{53}")
      (resp.json \ refresh_token).as[String] must beMatching(".{53}")
      (resp.json \ token_type).as[String] must equalTo("bearer")
      (resp.json \ scope).as[String] must equalTo("global")
      (resp.json \ expires_in).as[Int] must beGreaterThan(0)
    }

    "respond with 200 and correct access token to refresh token created by client_credentials" in new WithServer(port = 3333) {
      import oauth2.spec.AccessTokenResponseParams._
      val c = Oauth.storeClient(Oauth2Client("the_client", hash("pass"),
        Seq("global"), Seq(GrantTypes.client_credentials, GrantTypes.refresh_token),
        RedirectUri, Seq(), 3600, 3600, None, true))
      val resp = postf("/oauth/token", grant_type -> GrantTypes.client_credentials, "scope" -> "global")(Some(c))
      val refToken = (resp.json \ refresh_token).as[String]
      resp.status must equalTo(200)
      val accessResp = postf1("/oauth/token", refresh_token -> refToken, grant_type -> GrantTypes.refresh_token)
      accessResp.status must equalTo(200)
      (accessResp.json \ access_token).as[String] must beMatching(".{53}")
      (accessResp.json \ token_type).as[String] must equalTo("bearer")
      (accessResp.json \ scope).as[String] must equalTo("global")
      (accessResp.json \ expires_in).as[Int] must beGreaterThan(0)
    }
  }
}
