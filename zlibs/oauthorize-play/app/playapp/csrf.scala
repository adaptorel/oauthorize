package oauthorize.playapp.csrf

import play.api.mvc._
import oauthorize.model.{ OauthResponse, OauthRequest, InitiateAuthzApproval }
import oauthorize.service.Oauth2Config
import oauthorize.grants.UserApproval
import play.api.http.HeaderNames._
import play.api.libs.concurrent.Execution.Implicits.defaultContext
import play.api.libs.Crypto
import play.filters.csrf.CSRFFilter
import play.filters.csrf.CSRF.{ TokenProvider, SignedTokenProvider, UnsignedTokenProvider }
import OauthorizeCsrf._

/**
 * Adding the CSRF token value to the InitialAuthzApproval, only if the client
 * is auto approve==true and will not pass through the normal user approval form
 * POST. Obviously this will only work with Play's CSRF enabled an Oauthorize's
 * CSRF disabled.
 */
object WithCsrf {
  def apply(req: RequestHeader, response: OauthResponse): OauthResponse = {
    /*
     * If Oauthorize CSRF token not present, try Play's CSRF token 
     */
    val token = OauthorizeCsrf.getToken(req).map(_.value) orElse
      play.filters.csrf.CSRF.getToken(req).map(_.value)
    response match {
      case a: InitiateAuthzApproval if (token.isDefined && a.client.autoapprove) =>
        debug(s"Adding existing session/tag token to InitiateAuthzApproval Oauthorize response: $token")
        a.copy(csrfToken = token)
      case any => any
    }
  }
}

object CsrfCheck {
  def apply(req: RequestHeader, a: OauthRequest)(block: => OauthResponse): OauthResponse = {
    /*
     * ONLY perform the check if there's a token in the session which
     * means the filter is enabled
     */
    val isCsrfCheckNeeded = OauthorizeCsrf.getToken(req).isDefined
    if (!isCsrfCheckNeeded) {
      debug("CSRF token not needed, skipping check")
      block
    } else {
      debug(s"CSRF token in request: ${a.param(OauthorizeCsrf.TokenName)}")
      debug(s"CSRF token in session: ${OauthorizeCsrf.getToken(req)}");
      val csrfVerifies = (for {
        queryToken <- a.param(OauthorizeCsrf.TokenName)
        sessionToken <- OauthorizeCsrf.getToken(req)
      } yield {
        OauthorizeCsrfConf.defaultTokenProvider.compareTokens(queryToken, sessionToken.value)
      }) getOrElse (false)
      if (!csrfVerifies)
        throw new IllegalStateException("CSRF token check failed")
      else {
        debug(s"CSRF token check succeeded, moving along")
        block
      }
    }
  }
}

/**
 * CSRF implementation adapted from Play CSRFFilter but applied only to
 * Oauthorize user approval URL
 *
 * Also, it should not interfere in any way with apps that have Play's default
 * CSRF enabled.
 *
 * However, if the app is already using CSRF we do recommend disabling the
 * Oauthorize support. The only change needed would be overriding the user
 * approval page and adding the CSRF token hidden field just as with any page
 */

object OauthorizeCsrfFilter {
  def apply(
    tokenName: => String = OauthorizeCsrfConf.TokenName,
    cookieName: => Option[String] = OauthorizeCsrfConf.CookieName,
    secureCookie: => Boolean = OauthorizeCsrfConf.SecureCookie,
    createIfNotFound: (RequestHeader) => Boolean = OauthorizeCsrfConf.defaultCreateIfNotFound,
    tokenProvider: => TokenProvider = OauthorizeCsrfConf.defaultTokenProvider) = {
    new CSRFFilter(tokenName, cookieName, secureCookie, createIfNotFound, tokenProvider) {
      override def apply(next: EssentialAction): EssentialAction =
        new OauthorizeCsrfAction(next, tokenName, cookieName, secureCookie,
          createIfNotFound, tokenProvider)
    }
  }
}

class OauthorizeCsrfAction(
  next: EssentialAction,
  tokenName: String = OauthorizeCsrfConf.TokenName,
  cookieName: Option[String] = OauthorizeCsrfConf.CookieName,
  secureCookie: Boolean = OauthorizeCsrfConf.SecureCookie,
  createIfNotFound: RequestHeader => Boolean = OauthorizeCsrfConf.defaultCreateIfNotFound,
  tokenProvider: TokenProvider = OauthorizeCsrfConf.defaultTokenProvider)
  extends EssentialAction {

  override def apply(request: RequestHeader) = {
    if (shouldAddCsrf(request, tokenName, cookieName)) {

      debug(s"CSRF token not found, adding it to request/session: ${request.method} ${request.path}")

      // No token in header and we have to create one if not found, so create a new token
      val newToken = tokenProvider.generateToken

      // The request
      val requestWithNewToken = request.copy(tags = request.tags + (Token.RequestTag -> newToken))

      // Once done, add it to the result
      next(requestWithNewToken).map(result =>
        addTokenToResponse(tokenName, cookieName, secureCookie, newToken, request, result))
    } else next(request)
  }

  private def addTokenToResponse(tokenName: String, cookieName: Option[String], secureCookie: Boolean,
    newToken: String, request: RequestHeader, result: SimpleResult) = {

    if (isCached(result)) {
      debug("Not adding CSRF token to cached response")
      result
    } else {
      debug(s"Adding CSRF token to session on response: $result")
      cookieName.map {
        // cookie
        name =>
          result.withCookies(Cookie(name, newToken, path = Session.path, domain = Session.domain,
            secure = secureCookie))
      } getOrElse {

        //val newSession = result.session(request) + (tokenName -> newToken)
        // Get the new session, or the incoming session
        val session = Cookies(result.header.headers.get(SET_COOKIE))
          .get(Session.COOKIE_NAME).map(_.value).map(Session.decode)
          .getOrElse(request.session.data)
        val newSession = session + (tokenName -> newToken)
        val res = result.withCookies(request.cookies.toSeq: _*).withSession(Session.deserialize(newSession))
        debug(s"Added CSRF token to session on response: $result")
        res
      }
    }

  }

  private[csrf] def isCached(result: SimpleResult): Boolean =
    result.header.headers.get(CACHE_CONTROL).fold(false)(!_.contains("no-cache"))

  private def shouldAddCsrf(request: RequestHeader, tokenName: String, cookieName: Option[String]) = {
    request.method == "GET" && cookieName.flatMap(cookie => request.cookies.get(cookie).map(_.value))
      .orElse(request.session.get(tokenName)).isEmpty
  }
}

object OauthorizeCsrf {

  import play.api.Logger

  val logger = Logger("oauthorize.csrf")

  def debug(message: String) = if (logger.isDebugEnabled) logger.debug(message)

  /**
   * A CSRF token
   */
  case class Token(value: String)

  object Token {
    val RequestTag = "OAUTHORIZE_CSRF_TOKEN"
  }

  // Allows the template helper to access it
  def TokenName = OauthorizeCsrfConf.TokenName

  import OauthorizeCsrfConf._

  /**
   * Extract token from current request
   */
  def getToken(request: RequestHeader): Option[Token] = {
    // First check the tags, this is where tokens are added if it's added to the current request
    val token = request.tags.get(Token.RequestTag)
      // Check cookie if cookie name is defined
      .orElse(CookieName.flatMap(n => request.cookies.get(n).map(_.value)))
      // Check session
      .orElse(request.session.get(TokenName))
    if (SignTokens) {
      // Extract the signed token, and then resign it. This makes the token random per request, preventing the BREACH
      // vulnerability
      token.flatMap(Crypto.extractSignedToken)
        .map(token => Token(Crypto.signToken(token)))
    } else {
      token.map(Token.apply)
    }
  }
}

object OauthorizeCsrfConf {
  import play.api.Play.current
  import play.api.mvc.Session

  def c = current.configuration

  lazy val TokenName: String = c.getString("oauthorize.csrf.token.name").getOrElse("oauthorize_csrf_token")
  lazy val CookieName: Option[String] = c.getString("oauthorize.csrf.cookie.name")
  lazy val SecureCookie: Boolean = c.getBoolean("oauthorize.csrf.cookie.secure").getOrElse(Session.secure)
  lazy val PostBodyBuffer: Long = c.getBytes("oauthorize.csrf.body.bufferSize").getOrElse(102400L)
  lazy val SignTokens: Boolean = c.getBoolean("oauthorize.csrf.sign.tokens").getOrElse(true)

  def defaultCreateIfNotFound(request: RequestHeader) = {
    // If the request isn't accepting HTML, then it won't be rendering a form, so there's no point in generating a
    // CSRF token for it.
    request.method == "GET" && (request.accepts("text/html") || request.accepts("application/xml+xhtml"))
    //request.method == "GET"
  }
  def defaultTokenProvider = {
    if (SignTokens) {
      SignedTokenProvider
    } else {
      UnsignedTokenProvider
    }
  }
}