package grants.playimpl

import play.api.mvc.RequestHeader
import org.apache.commons.codec.binary.Base64
import oauthorize.model.ClientAuthentication

object BasicAuthentication {

  def apply(request: RequestHeader) = {
    request.headers.get("Authorization").filter(_.startsWith("Basic ")) flatMap { authHeader =>
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

  def apply(request: RequestHeader) = {
    request.headers.get("Authorization").filter(_.startsWith("Bearer ")) map { authHeader =>
      authHeader.replaceAll("Bearer ", "")
    }
  }
}