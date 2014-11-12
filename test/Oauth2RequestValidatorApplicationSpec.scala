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
import oauthorize.sample.Oauth
import play.api.libs.ws.WS
import com.ning.http.client.Realm
import play.api.libs.ws.WS.WSRequestHolder
import play.api.libs.ws.Response
import play.api.libs.ws.Response
import oauth2.spec.ResponseType

@RunWith(classOf[JUnitRunner])
class Oauth2RequestValidatorApplicationSpec extends PlaySpecification with TestHelpers {

  "Application global validator should" should {

    "send 400 if response_type is missing" in new WithServer(port = 3333) {
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $response_type in [${ResponseType.code}, ${ResponseType.token}]"))
    }

    "send 400 if response_type is wrong" in new WithServer(port = 3333) {
      val resp = await(WS.url(s"$TestUri/oauth/authorize?response_type=eww").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $response_type in [${ResponseType.code}, ${ResponseType.token}]"))
    }

    "send 400 if client_id is missing" in new WithServer(port = 3333) {
      val resp = await(WS.url(s"$TestUri/oauth/authorize?response_type=code").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }

    "send 400 if redirect_uri is wrong" in new WithServer(port = 3333) {
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=code").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $client_id, $response_type, $redirect_uri, $scope"))
    }

    s"send 400 if not POST" in new WithServer(port = 3333) {
      val resp = await(WS.url(s"$TestUri/oauth/token").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString("mandatory: HTTPS POST"))
    }
    
    s"send 400 if not application/x-www-form-urlencoded" in new WithServer(port = 3333) {
      val resp = await(WS.url(s"$TestUri/oauth/token").post("grant_type=refresh_token&refresh_token=ttt"))
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString("mandatory: Content-Type -> application/x-www-form-urlencoded"))
    }    

    s"send 400 if '$grant_type' param is missing" in new WithServer(port = 3333) {
      val resp = post("/oauth/token")
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString("invalid grant type"))
    }

    s"send 400 if '$grant_type' param is invalid" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> "whatever", code -> "whatever")
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString("invalid grant type"))
    }
  }
}
