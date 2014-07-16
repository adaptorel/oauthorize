package oauthorize

object utils {

  import oauth2.spec.Error._
  import oauth2.spec.StatusCodes._
  import oauthorize.model.Err
  import java.util.UUID
  import org.apache.commons.codec.binary.Hex
  import java.security.MessageDigest

  val ScopeSeparator = " "

  def err(err: String, statusCode: Int): Err = {
    Err(err, None, None, None, statusCode)
  }

  def err(error: String, desc: String, statusCode: Int = BadRequest): Err = {
    err(error, desc, statusCode, null)
  }

  def err(err: String, desc: String, statusCode: Int, redirectUri: String): Err = {
    Err(err, Some(desc), None, Option(redirectUri), statusCode)
  }

  private def sha256UUID() = {
    sha256(UUID.randomUUID.toString)
  }

  def sha256(value: String) = {
    new String(Hex.encodeHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes("UTF-8"))))
  }

  import java.net.URLEncoder
  def encodedQueryString(uri: String, params: Map[String, String], prefix: String = "?"): String = {
    def valueOf(x: Any) = x match {
      case Some(v) => URLEncoder.encode(v.toString, "UTF8")
      case v => URLEncoder.encode(v.toString, "UTF8")
    }
    uri + params.filter(a => a._2 != None && Option(a._2).isDefined).map(v => s"${v._1}=${valueOf(v._2)}")
      .mkString(Option(prefix).getOrElse("?"), "&", "")
  }
}