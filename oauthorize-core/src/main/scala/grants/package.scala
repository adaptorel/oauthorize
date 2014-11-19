package oauthorize

package object grants {
  import oauth2.spec.StatusCodes
  import scala.concurrent.Future
  import utils._
  
  //this method is here only to improve readability
  def error(code: String, desc: String, httpStatus: Int = StatusCodes.BadRequest) = {
    Future.successful(Left(err(code, desc, httpStatus)))
  }
}

