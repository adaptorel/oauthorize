package oauthorize.test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthorize.model._
import java.net.URLDecoder
import play.api.libs.ws.WS
import scala.concurrent.Await
import scala.concurrent.Future
import scala.concurrent.duration._
import oauth2.spec.ResponseType
import play.api.Play
import oauthorize.service.Oauth2Store
import oauthorize.playapp.Oauth
import oauth2.spec.GrantTypes

@RunWith(classOf[JUnitRunner])
class AuthzRequestApplicationSpec extends PlaySpecification with TestHelpers {

  import oauthorize.service.TenantImplicits._
  
  "Application" should {

    s"send 400 if '$code' param is missing" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> GrantTypes.authorization_code)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $code, $redirect_uri"))
    }

    "send 400 if redirect_uri is not matching client's" in new WithServer(port = 3333) {
      val client = Oauth2Client("a", SecretInfo("a"), Seq("internal"), Seq("authorization_code"), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=code&scope=internal&redirect_uri=wrongredirect").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"missmatched: $redirect_uri"))
    }
    
    "respond with 400 if incorrect scope" in new WithServer(port = 3333) {
      val client = Oauth2Client("a", SecretInfo("a"), Seq("internal"), Seq("authorization_code"), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=code&scope=broken&redirect_uri=$RedirectUri").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_scope))
      (resp.json \ "error_description") must equalTo(JsString("unsupported scope"))
    }

    "send 400 if response_type=code and authorization_code unsupported" in new WithServer(port = 3333) {
      val client = Oauth2Client("a", SecretInfo("a"), Seq("internal"), Seq(GrantTypes.password), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=code&state=555&redirect_uri=$RedirectUri&scope=internal")
        .withHeaders("Cookie" -> authenticatedCookie).withFollowRedirects(false).get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(unsupported_response_type))
      (resp.json \ "error_description") must equalTo(JsString("unsupported grant type"))  
    }
    
    "send 400 if response_type=token and implicit unsupported" in new WithServer(port = 3333) {
      val client = Oauth2Client("a", SecretInfo("a"), Seq("internal"), Seq(GrantTypes.password), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=token&state=555&redirect_uri=$RedirectUri&scope=internal")
        .withHeaders("Cookie" -> authenticatedCookie).withFollowRedirects(false).get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(unsupported_response_type))
      (resp.json \ "error_description") must equalTo(JsString("unsupported grant type"))  
    }    
    
    "send 302 if response_type is correct" in new WithServer(port = 3333, app = FakeLoginApp) {
      val authzCode = AuthzHelper.authorizationRequest
      URLDecoder.decode(authzCode, "utf-8") must beMatching(".{53}")
    }

    "send 302 and hash uri if implicit grant type" in new WithServer(port = 3333) {
      val client = Oauth2Client("a", SecretInfo("a"), Seq("internal"), Seq("authorization_code", "implicit"), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=token&state=555&redirect_uri=$RedirectUri&scope=internal")
        .withHeaders("Cookie" -> authenticatedCookie).withFollowRedirects(true).get)
      /*
       *  ERROR again cause it passes everything and eventually redirects to the
       *  callback redirect URI which doesn't exist
       */  
      val expectedUri = resp.ahcResponse.getUri.toString
      val Regex = ".*#access_token=(.*)&token_type=(.*)&expires_in=(.*)&scope=(.*)&state=(.*)".r
      val Regex(accessToken, tokenType, expiresIn, scope, state) = expectedUri
      URLDecoder.decode(accessToken, "utf-8") must beMatching(".{53}")
      tokenType must equalTo("bearer")
      expiresIn.toInt must be greaterThan (3500)
      scope must equalTo("internal")
      state must equalTo("555")
    }
  }
}

object AuthzHelper extends TestHelpers {
  import oauthorize.service.TenantImplicits._
  def authorizationRequest(): String = {
    import oauth2.spec.AccessTokenResponseParams._
    Oauth.storeClient(Oauth2Client("the_client", hash("pass"), Seq("global"), Seq(GrantTypes.authorization_code, refresh_token), RedirectUri, Seq(), 3600, 3600, None, true))
    val authzResp = await(WS.url(s"$TestUri/oauth/authorize?client_id=the_client&response_type=code&state=555&scope=global&redirect_uri=$RedirectUri")
      .withHeaders("Cookie" -> authenticatedCookie)
      .withFollowRedirects(true).get)
    val P = """.*?code=(.*)&state=555""".r
    /*
       * if successful authentication and authz code generation we extract the code
       * from the erred request following the callback redirect. it's enough to extract
       * the code from it
       */
    val P(authzCode) = authzResp.getAHCResponse.getUri.toString
    authzCode
  }
}
