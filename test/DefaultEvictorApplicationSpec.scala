package oauthorize.test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import oauth2.spec.GrantTypes
import oauthorize.service._
import oauthorize.playapp._
import oauthorize.model._

@RunWith(classOf[JUnitRunner])
class ZDefaultEvictorApplicationSpec extends PlaySpecification with TestHelpers {

  import oauthorize.service.TenantImplicits._
  
  lazy val evictor = new DefaultEvictor with Oauth2DefaultsPlay with InMemoryOauth2Store

  "Application" should {
    
    "correctly remove expired authorization code requests" in new WithServer(port = 3333) {
      val client = Oauth2Client("the_client", hash("pass"), Seq("global"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), RedirectUri, Seq(), 3600, 3600, None, true)
      val authzRequest = AuthzRequest(Some("1a11a"), "WEB_APP", "", "", Seq("internal"), true, 2, System.currentTimeMillis, None, None)
      Oauth.storeAuthzRequest("1a11a", authzRequest)
      Thread.sleep(2 * 1000)
      Oauth.getAuthzRequest("1a11a") must beSome
      val evictedCount = evictor.evictAll
      evictedCount must beGreaterThan(0)
      Oauth.getAuthzRequest("1a11a") must beNone
    }
    
    "correctly remove expired access tokens" in new WithServer(port = 3333) {
      val client = Oauth2Client("the_client", hash("pass"), Seq("global"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), RedirectUri, Seq(), 3600, 3600, None, true)
      val token = AccessToken("1a11a", "WEB_APP", Seq("internal"), 1, System.currentTimeMillis, None)
      Oauth.storeTokens(new AccessAndRefreshTokens(token), client)
      Thread.sleep(2 * 1000)
      Oauth.getAccessToken("1a11a") must beSome
      val evictedCount = evictor.evictAll
      evictedCount must beGreaterThan(0)
      Oauth.getAccessToken("1a11a") must beNone
    }

    "correctly remove expired refresh tokens" in new WithServer(port = 3333) {
      val client = Oauth2Client("the_client", hash("pass"), Seq("global"), Seq(GrantTypes.authorization_code, GrantTypes.refresh_token), RedirectUri, Seq(), 3600, 3600, None, true)
      val aToken = AccessToken("1a11a", "WEB_APP", Seq("internal"), 1, System.currentTimeMillis, None)
      val rToken = RefreshToken("r1a11a", "WEB_APP", Seq("internal"), 1, System.currentTimeMillis, None)
      Oauth.storeTokens(new AccessAndRefreshTokens(aToken, Some(rToken)), client)
      Thread.sleep(2 * 1000)
      Oauth.getRefreshToken("r1a11a") must beSome
      val evictedCount = evictor.evictAll
      evictedCount must beGreaterThan(0)
      Oauth.getRefreshToken("r1a11a") must beNone
    }
  }

}