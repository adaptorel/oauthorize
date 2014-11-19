package oauthorize.test

import org.junit.runner.RunWith
import org.specs2.mutable.Specification
import oauthorize.service.Sha256ClientSecretHasher
import org.specs2.runner.JUnitRunner
import oauthorize.model.SecretInfo

@RunWith(classOf[JUnitRunner])
class Sha256PasswordEncoderSpec extends Specification {

  "The SHA256 encoder should" should {

    val enc = new Sha256ClientSecretHasher
    s"fail if original encoded password doesn't match" in {
      enc.secretMatches("pass", SecretInfo("whateverpass")) must beFalse
    }
    s"encoded passwords should match" in {
      val pass = enc.hashSecret(SecretInfo("pass"))
      enc.secretMatches("pass", pass) must beTrue
    }
    s"encoded passwords with salt should match" in {
      val pass = enc.hashSecret(SecretInfo("pass", Some("salt")))
      enc.secretMatches("pass", pass) must beTrue
    }
  }
}
