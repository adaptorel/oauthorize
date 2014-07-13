package test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import play.api.test._
import play.api.test.Helpers._
import oauth2.spec.ResponseType
import oauth2.spec.Req._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Error._
import oauthorize.model._
import play.api.libs.json.Json
import play.api.libs.json.JsString
import oauthorize.service.BCryptPasswordEncoder

@RunWith(classOf[JUnitRunner])
class BCryptPasswordEncoderSpec extends Specification {

  "The BCrypt encoder should" should {

    val enc = new BCryptPasswordEncoder {}
    s"fail if original encoded password doesn't match" in {
      enc.passwordMatches("pass", "whateverpass") must beFalse
    }
    s"encoded passwords should match" in {
      val pass = enc.encodePassword("pass")
      enc.passwordMatches("pass", pass) must beTrue
    }
  }
}
