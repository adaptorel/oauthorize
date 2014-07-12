package grants

import oauthze.model.OauthRequest

trait Dispatcher {
  def matches(request: OauthRequest): Boolean
}