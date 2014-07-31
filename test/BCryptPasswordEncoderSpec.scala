package oauthorize.test

import org.junit.runner.RunWith
import org.specs2.mutable.Specification
import oauthorize.service.BCryptClientSecretHasher
import org.specs2.runner.JUnitRunner
import oauthorize.model.SecretInfo

@RunWith(classOf[JUnitRunner])
class BCryptPasswordEncoderSpec extends Specification {

  "The BCrypt encoder should" should {

    val enc = new BCryptClientSecretHasher {}
    s"fail if original encoded password doesn't match" in {
      enc.clientSecretMatches("pass", SecretInfo("whateverpass")) must beFalse
    }
    s"encoded passwords should match" in {
      val pass = enc.hashClientSecret(SecretInfo("pass"))
      enc.clientSecretMatches("pass", pass) must beTrue
    }
  }
}
