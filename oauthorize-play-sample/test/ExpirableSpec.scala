package oauthorize.test

import org.specs2.mutable._
import org.specs2.runner._
import org.junit.runner._
import oauth2.spec.ResponseType
import oauth2.spec.Req._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Error._
import oauthorize.model._

@RunWith(classOf[JUnitRunner])
class ExpirableSpec extends Specification {

  "An expirable should" should {

    "expire correctly" in {
      AccessToken("a", "a", Seq(), 3000, System.currentTimeMillis - (4000 * 1000), None).isExpired must beTrue
      AccessToken("a", "a", Seq(), 3000, System.currentTimeMillis - (2000 * 1000), None).isExpired must beFalse
    }
    
    "compute validity remaining correctly" in {
      AccessToken("a", "a", Seq(), 3000, System.currentTimeMillis - (4000 * 1000), None).validityRemaining must beLessThan(0L)
      AccessToken("a", "a", Seq(), 3000, System.currentTimeMillis - (2000 * 1000), None).validityRemaining must beGreaterThan(0L)
    }
  }
}
