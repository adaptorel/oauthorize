package oauthorize.grants

import oauthorize.model.OauthRequest

trait Dispatcher {
  def matches(request: OauthRequest): Boolean
}