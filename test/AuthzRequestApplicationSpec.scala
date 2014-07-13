package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import play.api.libs.json._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthze.model._
import java.net.URLDecoder
import play.api.libs.ws.WS
import scala.concurrent.Await
import scala.concurrent.Future
import scala.concurrent.duration._
import oauth2.spec.ResponseType
import play.api.Play
import oauthze.service.OauthClientStore
import app.Oauth

@RunWith(classOf[JUnitRunner])
class AuthzRequestApplicationSpec extends PlaySpecification {

  val RedirectUri = "http://www.r.com/cb"
  val port = 3333  
  val TestUri = s"http://localhost:$port"  
  
  "Application" should {

    "send 400 if response_type is missing" in new WithServer(port=3333) {
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $response_type in [${ResponseType.code}, ${ResponseType.token}]"))
    }    
    
    "send 400 if response_type is wrong" in new WithServer(port=3333) {
      val resp = await(WS.url(s"$TestUri/oauth/authorize?response_type=eww").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $response_type in [${ResponseType.code}, ${ResponseType.token}]"))
    }    
    
    "send 400 if client_id is missing" in new WithServer(port=3333) {
      val resp = await(WS.url(s"$TestUri/oauth/authorize?response_type=code").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }

    "send 400 if redirect_uri is wrong" in new WithServer(port=3333) {
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=code").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }
    
    "send 400 if redirect_uri is not matching client's" in new WithServer(port=3333) {
      val client = Oauth2Client("a", "a", Seq("internal"), Seq("authorization_code"), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=code&scope=internal&redirect_uri=wrongredirect").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"missmatched: $redirect_uri"))
    }

    "send 302 if response_type is correct" in new WithServer(port=3333) {
      val client = Oauth2Client("a", "a", Seq("internal"), Seq("authorization_code"), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val CodeParamRegex = """.*\?code=(.*)&state=555""".r
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=code&state=555&redirect_uri=$RedirectUri&scope=internal").get)
      resp.status must equalTo(302)
      val expectedUri = resp.header("Location").get
      val CodeParamRegex(authzCode) = expectedUri
      URLDecoder.decode(authzCode, "utf-8") must beMatching(".{53}")
      expectedUri must beMatching(".*state=555.*")
    }
    
    "send 302 and hash uri if implicit grant type" in new WithServer(port=3333) {
      val client = Oauth2Client("a", "a", Seq("internal"), Seq("authorization_code", "implicit"), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=token&state=555&redirect_uri=$RedirectUri&scope=internal").get)
      val expectedUri = resp.header("Location").get
      val Regex = ".*#access_token=(.*)&token_type=(.*)&expires_in=(.*)&scope=(.*)&state=(.*)".r
      val Regex(accessToken, tokenType, expiresIn, scope, state) = expectedUri
      URLDecoder.decode(accessToken, "utf-8") must beMatching(".{53}")
      tokenType must equalTo("bearer")
      expiresIn.toInt must be greaterThan(3500)
      scope must equalTo("internal")
      state must equalTo("555")
    }
  }
}
