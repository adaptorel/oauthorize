package oauth2.spec

object model {
  import TokenType._
  trait Oauth2Response
  case class AuthzCodeResponse(code: String, state: Option[String]) extends Oauth2Response
  case class ImplicitResponse(access_token: String, token_type: String = bearer, expires_in: Long, scope: String, state: Option[String]) extends Oauth2Response
  case class AccessTokenResponse(access_token: String, refresh_token: Option[String], token_type: String = bearer, expires_in: Long, scope: String) extends Oauth2Response
}

object GrantTypes {
  val authorization_code = "authorization_code"
  val password = "password"
  val client_credentials = "client_credentials"
  val refresh_token = "refresh_token"
  val implic1t = "implicit"
}

object Req {
  val client_id = "client_id"
  val state = "state"
  val response_type = "response_type"
  val redirect_uri = "redirect_uri"
  val scope = "scope"
  val grant_type = "grant_type"
  val code = "code"
}

/**
 * Do not ever import ResponseType._ as code clashes with Req.code
 * As ResponseType has a much more limited usage scope, always use
 * ResponseType.code and ResponseType.token
 */
object ResponseType {
  val code = "code"
  val token = "token"
}

object Error {
  val error = "error"
  val error_description = "error_description"
  val error_uri = "error_uri"
}

object AuthzErrors {
  val invalid_request = "invalid_request"
  val unauthorized_client = "unauthorized_client"
  val access_denied = "access_denied"
  val unsupported_response_type = "unsupported_response_type"
  val invalid_scope = "invalid_scope"
  val server_error = "server_error"
  val temporarily_unavailable = "temporarily_unavailable"
}

object AccessTokenErrors {
  val invalid_request = "invalid_request"
  val invalid_client = "invalid_client"
  val invalid_grant = "invalid_grant"
  val unauthorized_client = "unauthorized_client"
  val unsupported_response_type = "unsupported_response_type"
  val invalid_scope = "invalid_scope"
  val server_error = "server_error"
  val temporarily_unavailable = "temporarily_unavailable"
}

object AccessTokenResponse {
  val access_token = "access_token"
  val refresh_token = "refresh_token"
  val scope = "scope"
  val expires_in = "expires_in"
  val token_type = "token_type"
}

object TokenType {
  val bearer = "bearer"
}