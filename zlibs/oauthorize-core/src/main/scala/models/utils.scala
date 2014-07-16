package oauthorize

object utils {

  import oauth2.spec.Error._
  import oauth2.spec.StatusCodes._
  import oauthorize.model.{ Err, OauthRequest, ClientAuthentication }
  import org.apache.commons.codec.binary.{ Hex, Base64 }
  import java.security.MessageDigest
  import java.util.UUID

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

  object BasicAuthentication {

    def apply(request: OauthRequest) = {
      request.header("Authorization").filter(_.startsWith("Basic ")) flatMap { authHeader =>
        fromBase64(authHeader.replaceAll("Basic ", ""))
      }
    }

    private def fromBase64(base64: String): Option[ClientAuthentication] = {
      val clientIdAndPassword = new String(Base64.decodeBase64(base64.getBytes("UTF-8"))).split(":")
      if (clientIdAndPassword.length == 2) {
        Some(ClientAuthentication(clientIdAndPassword(0), clientIdAndPassword(1)))
      } else None
    }
  }

  object BearerAuthentication {

    def apply(request: OauthRequest) = {
      request.header("Authorization").filter(_.startsWith("Bearer ")) map { authHeader =>
        authHeader.replaceAll("Bearer ", "")
      }
    }
  }
}