package oauthorize.playapp

import oauthorize.grants._
import oauthorize.hash._
import grants._
import oauthorize.service._
import play.api.mvc.WithFilters
import csrf.OauthorizeCsrfFilter

import oauth2provider._

object Oauth2RequestValidator extends Oauth2RequestValidatorPlay(config, logger, oauth2Validator)
object AuthorizationCodeGrant extends AuthorizationCodePlay(config, logger, authzCodeEndpoint)
object ImplicitGrant extends ImplicitGrantPlay(config, logger, implicitGrantEndpoint)
object ClientCredentialsGrant extends ClientCredentialsGrantPlay(config, logger, clientCredentialsEndpoint)
object AccessTokenEndpoint extends AccessTokenEndpointPlay(config, logger, accessTokenEnpoint)
object RefreshTokenEndpoint extends RefreshTokenEndpointPlay(config, logger, refreshTokenEndpoint)
object ResourceOwnerCredentialsGrant extends ResourceOwnerCredentialsGrantPlay(config, logger, resourceOwnerEndpoint)
object UserApprovalEndpoint extends UserApprovalPlay(config, logger, store, userApprovalEndpoint)

class Oauth2Filters extends WithFilters(
  OauthorizeCsrfFilter(),
  Oauth2RequestValidator,
  AuthorizationCodeGrant,
  ImplicitGrant,
  ClientCredentialsGrant,
  ResourceOwnerCredentialsGrant,
  AccessTokenEndpoint,
  RefreshTokenEndpoint,
  UserApprovalEndpoint) with Oauth2GlobalErorrHandler
  
object oauth2provider {
  val config = new PlayOauth2Config
  val logger = new PlayLogging
  val store = new InMemoryOauth2Store
  val tokens = new DefaultTokenGenerator(Option(new BCryptHasher(10)))
  val users = new SecureSocialUserStore

  val clientSecretHasher = new Sha256ClientSecretHasher
  val userPasswordHasher = new BCryptUserPasswordHasher(10)

  val authzDeserializer = new JsonAuthzDeserializer

  val oauth2Validator = new Oauth2RequestValidator(config, logger)
  val authzCodeEndpoint = new AuthorizationCode(config, store)
  val implicitGrantEndpoint = new ImplicitGrant(config, store)
  val clientCredentialsEndpoint = new ClientCredentialsGrant(config, store, clientSecretHasher, tokens)
  val accessTokenEnpoint = new AccessTokenEndpoint(config, store, clientSecretHasher, tokens)
  val refreshTokenEndpoint = new RefreshTokenEndpoint(config, store, clientSecretHasher, tokens)
  val resourceOwnerEndpoint = new ResourceOwnerCredentialsGrant(config, store, clientSecretHasher, users, userPasswordHasher, tokens)
  val userApprovalEndpoint = new UserApproval(config, store, tokens, authzDeserializer)
}  
