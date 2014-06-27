package controllers

object a {
  def main(args: Array[String]) {
    println(new AuthzRequest(null, null, None, None, Seq()).getError)
  }
}