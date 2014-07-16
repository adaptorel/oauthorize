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

  "Application" should {

    s"send 400 if '$code' param is missing" in new WithServer(port = 3333) {
      val resp = postf1("/oauth/token", grant_type -> GrantTypes.authorization_code)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"mandatory: $grant_type, $code, $redirect_uri"))
    }

    "send 400 if redirect_uri is not matching client's" in new WithServer(port = 3333) {
      val client = Oauth2Client("a", "a", Seq("internal"), Seq("authorization_code"), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=code&scope=internal&redirect_uri=wrongredirect").get)
      resp.status must equalTo(400)
      (resp.json \ "error") must equalTo(JsString(invalid_request))
      (resp.json \ "error_description") must equalTo(JsString(s"missmatched: $redirect_uri"))
    }

    //TODO This fails now because we must fake a logged in user with SecureSocial for the approval to pass
    "send 302 if response_type is correct" in new WithServer(port = 3333) {
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

    "send 302 and hash uri if implicit grant type" in new WithServer(port = 3333) {
      val client = Oauth2Client("a", "a", Seq("internal"), Seq("authorization_code", "implicit"), RedirectUri, Seq(), 3600, 3600, None, true)
      Oauth.storeClient(client)
      val resp = await(WS.url(s"$TestUri/oauth/authorize?client_id=a&response_type=token&state=555&redirect_uri=$RedirectUri&scope=internal").get)
      val expectedUri = resp.header("Location").get
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
