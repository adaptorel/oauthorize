package oauthorize.test

import org.junit.runner.RunWith
import org.specs2.mutable.Specification
import oauthorize.service.BCryptClientSecretHasher
import org.specs2.runner.JUnitRunner
import oauthorize.model.SecretInfo

@RunWith(classOf[JUnitRunner])
class BCryptPasswordEncoderSpec extends Specification {

  "The BCrypt encoder should" should {

    val enc = new BCryptClientSecretHasher(10)
    s"fail if original encoded password doesn't match" in {
      enc.secretMatches("pass", SecretInfo("whateverpass")) must beFalse
    }
    s"encoded passwords should match" in {
      val pass = enc.hashSecret(SecretInfo("pass"))
      enc.secretMatches("pass", pass) must beTrue
    }
  }
}
