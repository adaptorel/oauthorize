package oauthorize.test

import org.junit.runner.RunWith
import org.specs2.mutable.Specification
import oauthorize.service.Sha256PasswordEncoder
import org.specs2.runner.JUnitRunner

@RunWith(classOf[JUnitRunner])
class Sha256PasswordEncoderSpec extends Specification {

  "The SHA256 encoder should" should {

    val enc = new Sha256PasswordEncoder {}
    s"fail if original encoded password doesn't match" in {
      enc.passwordMatches("pass", "whateverpass") must beFalse
    }
    s"encoded passwords should match" in {
      val pass = enc.encodePassword("pass")
      enc.passwordMatches("pass", pass) must beTrue
    }
  }
}
