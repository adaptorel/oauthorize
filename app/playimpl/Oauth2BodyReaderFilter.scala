package grants.playimpl

import oauth2.spec.AuthzErrors
import oauthorize.model.{OauthRequest, Logging, Dispatcher}
import play.api.libs.json.Json
import play.api.mvc._

import scala.concurrent.Future

trait Oauth2BodyReaderFilter extends EssentialFilter {

  this: Dispatcher with Logging =>

  import json._
  import play.api.libs.iteratee.{ Enumerator, Done, Iteratee, Traversable }
  import play.api.libs.concurrent.Execution.Implicits.defaultContext
  import play.api.mvc.BodyParsers.parse._
  import play.api.mvc.Results.InternalServerError
  import oauthorize.utils.err

  override def apply(nextFilter: EssentialAction) = new EssentialAction {
    def apply(requestHeader: RequestHeader) = {
      checkFormBody(requestHeader, nextFilter)
    }
  }

  def bodyProcessor(a: OauthRequest, req: RequestHeader): Option[Future[SimpleResult]] = {
    Some(Future.successful(InternalServerError(Json.toJson(err(AuthzErrors.server_error, "Not implemented")))))
  }

  private def checkFormBody = checkBody1[Map[String, Seq[String]]](tolerantFormUrlEncoded, identity, bodyProcessor) _
  private def checkBody1[T](parser: BodyParser[T], extractor: (T => Map[String, Seq[String]]), processor: (OauthRequest, RequestHeader) => Option[Future[SimpleResult]])(request: RequestHeader, nextAction: EssentialAction) = {
    val firstPartOfBody: Iteratee[Array[Byte], Array[Byte]] =
      Traversable.take[Array[Byte]](50000) &>> Iteratee.consume[Array[Byte]]()

    firstPartOfBody.flatMap { bytes: Array[Byte] =>
      val parsedBody = Enumerator(bytes) |>>> parser(request)
      Iteratee.flatten(parsedBody.flatMap { parseResult =>
        val bodyAsMap = parseResult.fold(
          msg => { warn(msg.toString); Map[String, Seq[String]]() },
          body => ({
            for {
              values <- extractor(body)
            } yield values
          }))
        process(bodyAsMap ++ request.queryString, request, nextAction, bytes)
      })
    }
  }

  private def process(bodyAndQueryStringAsMap: Map[String, Seq[String]], request: RequestHeader, nextAction: EssentialAction, bytes: Array[Byte]): Future[Iteratee[Array[Byte], SimpleResult]] = {
    val r = new OauthRequest() {
      override val path = request.path
      override val method = request.method
      override def param(key: String) = params.get(key)
      override def header(key: String) = headers.get(key)
      override val params = bodyAndQueryStringAsMap.map(x => (x._1 -> x._2.mkString))
      private val headers = request.headers
    }
    if (matches(r)) {
      debug("found matching processor " + r + ": " + this)
      bodyProcessor(r, request).fold(next(nextAction, bytes, request))(f => f.map(Done(_)))
    } else {
      debug("didn't find matching request, will just forward " + r + ": " + this)
      next(nextAction, bytes, request)
    }
  }

  private def next(nextAction: EssentialAction, bytes: Array[Byte], request: RequestHeader) = Future(Iteratee.flatten(Enumerator(bytes) |>> nextAction(request)))
}
