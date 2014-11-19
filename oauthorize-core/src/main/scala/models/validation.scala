package oauthorize.model

import oauthorize.utils._
import oauth2.spec.Req._
import oauth2.spec._
import scala.language.reflectiveCalls

object ValidationUtils {
  def errForEmpty(value: { def isEmpty: Boolean }, error: Err) = {
    Option(value).filter(!_.isEmpty) match {
      case Some(s: Any) => None
      case _ => Some(error)
    }
  }

  def errForEmptyString(value: String, error: Err) = {
    Option(value).filter(!_.trim.isEmpty) match {
      case Some(s: Any) => None
      case _ => Some(error)
    }
  }

  def errForScope(authScope: Seq[String])(implicit client: Oauth2Client): Option[Err] = {
    import oauth2.spec.AuthzErrors.{ invalid_request, invalid_scope }
    errForEmpty(authScope, err(invalid_request, s"mandatory: $scope")) orElse {
      if (client.invalidScopes(authScope)) Some(err(invalid_scope, "unsupported scope")) else None
    }
  }

  def errForScope(authScope: Option[String])(implicit client: Oauth2Client): Option[Err] = {
    errForScope(authScope.map(_.split(ScopeSeparator).toSeq).getOrElse(Seq()))
  }

  def errForGrantType(grantType: String, client: Oauth2Client) = {
    errForEmptyString(grantType, err(AccessTokenErrors.invalid_request, s"mandatory: $grant_type")) orElse {
      if (!client.authorizedGrantTypes.contains(grantType)) Some(err(AccessTokenErrors.unsupported_grant_type, s"unsupported grant type")) else None
    }
  }
}

import ValidationUtils._

trait AuthzRequestValidation {
  this: AuthzRequest =>

  import oauth2.spec.AuthzErrors._

  def getError(implicit client: Oauth2Client): Option[Err] = {
    errClientId orElse
      errResponseType orElse
      errRedirectUri orElse
      errForScope(authScope) orElse
      errForGrantTypes
  }

  private def errClientId = {
    errForEmptyString(clientId, err(invalid_request, s"mandatory: $client_id"))
  }

  private def errForGrantTypes(implicit client: Oauth2Client) = {
    if ((ResponseType.token == responseType && !client.authorizedGrantTypes.contains(GrantTypes.implic1t)) ||
      (ResponseType.code == responseType && !client.authorizedGrantTypes.contains(GrantTypes.authorization_code)))
      Some(err(unsupported_response_type, "unsupported grant type"))
    else
      None
  }

  private def errRedirectUri(implicit client: Oauth2Client) = {
    errForEmptyString(redirectUri, err(invalid_request, s"mandatory: $redirect_uri")) orElse
      (if (redirectUri != client.redirectUri) Some(err(invalid_request, s"missmatched: $redirect_uri")) else None)
  }

  private def errResponseType = {
    errForEmptyString(responseType, err(invalid_request, s"mandatory: $response_type")) orElse {
      responseType match {
        case ResponseType.code | ResponseType.token => None
        case _ => Some(err(invalid_request, s"mandatory: $response_type in ['${ResponseType.code}','${ResponseType.token}']"))
      }
    }
  }
}

trait AccessTokenRequestValidation {
  this: AccessTokenRequest =>

  import oauth2.spec.AccessTokenErrors._

  def getError(authzRequest: AuthzRequest, client: Oauth2Client): Option[Err] = {
    errClientId(authzRequest, client.clientId) orElse
      errForGrantType(grantType, client) orElse
      errCode(authzRequest) orElse
      errForUnmatchingRedirectUri(authzRequest)
  }

  private def errClientId(authzRequest: AuthzRequest, authenticatedClientId: String) = {
    if (authzRequest.clientId != authenticatedClientId) Some(err(invalid_grant, s"mismatched $client_id")) else None
  }

  private def errCode(authzRequest: AuthzRequest) = {
    errForEmptyString(authzCode, err(invalid_request, s"mandatory: $code"))
  }

  private def errForUnmatchingRedirectUri(authzRequest: AuthzRequest) = {
    errForEmptyString(redirectUri, err(invalid_request, s"mandatory: $redirect_uri")) orElse {
      if (authzRequest.redirectUri != redirectUri) Some(err(invalid_request, s"mismatched: $redirect_uri")) else None
    }
  }
}

trait RefreshTokenRequestValidation {
  this: RefreshTokenRequest =>

  import oauth2.spec.AccessTokenErrors._

  def getError(client: Oauth2Client): Option[Err] = {
    errForGrantType(grantType, client) orElse
      errRefreshToken
  }

  private def errRefreshToken = {
    errForEmptyString(refreshToken, err(invalid_request, s"mandatory: $refresh_token"))
  }
}

trait ResourceOwnerCredentialsRequestValidation {
  this: ResourceOwnerCredentialsRequest =>

  import oauth2.spec.AccessTokenErrors._

  def getError(implicit client: Oauth2Client): Option[Err] = {
    errForGrantType(grantType, client) orElse
      errUsername orElse
      errPassword orElse
      errForScope(authScope)
  }

  private def errGrantType(implicit client: Oauth2Client) = {
    errForEmptyString(grantType, err(invalid_request, s"mandatory: $grant_type")) orElse {
      if (!client.authorizedGrantTypes.contains(grantType)) Some(err(unsupported_grant_type, s"unsupported grant type")) else None
    }
  }

  private def errUsername = {
    errForEmptyString(username, err(invalid_request, s"mandatory: $username"))
  }

  private def errPassword = {
    errForEmptyString(password, err(invalid_request, s"mandatory: $password"))
  }
}

trait ClientCredentialsRequestValidation {
  this: ClientCredentialsRequest =>
  def getError(implicit client: Oauth2Client): Option[Err] =
    errForGrantType(grantType, client) orElse errForScope(authScope)
}
