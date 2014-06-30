package oauthze

object utils {

  import play.api.mvc.Request
  import play.api.libs.json.JsValue
  import play.api.libs.json.Json
  import oauth.spec.Error._
  import java.util.UUID
  import org.apache.commons.codec.binary.Hex
  import org.apache.commons.codec.binary.Base64
  import java.security.MessageDigest

  type GrantType = String
  type ResponseType = String
  type State = String

  val ScopeSeparator = " "

  def err(err: String): JsValue = {
    Json.obj(error -> err)
  }

  def err(err: String, desc: String): JsValue = {
    Json.obj(error -> err, error_description -> desc)
  }

  private def sha256UUID() = {
    sha256(UUID.randomUUID.toString)
  }

  def sha256(value: String) = {
    new String(Hex.encodeHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes("UTF-8"))))
  }

  case class BasicAuthentication(clientId: String, clientSecret: String)

  object BasicAuthentication {

    def apply[A](request: Request[A]) = {
      request.headers.get("Authorization").filter(_.startsWith("Basic ")) flatMap { authHeader =>
        BasicAuthentication.fromBase64(authHeader.replaceAll("Basic ", ""))
      }
    }

    private def fromBase64(base64: String): Option[BasicAuthentication] = {
      val clientIdAndPassword = new String(Base64.decodeBase64(base64.getBytes("UTF-8"))).split(":")
      if (clientIdAndPassword.length == 2) {
        Some(BasicAuthentication(clientIdAndPassword(0), clientIdAndPassword(1)))
      } else None
    }
  }
}