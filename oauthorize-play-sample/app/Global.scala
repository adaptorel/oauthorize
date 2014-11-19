import play.api.Application
import play.api.mvc.WithFilters
import oauthorize.model.Oauth2Client
import oauthorize.model.SecretInfo
import oauthorize.playapp.Oauth2Filters
import oauthorize.sample.Oauth

object Global extends Oauth2Filters {
  override def onStart(app: Application) = {
    app.configuration.getBoolean("with.test.data").map { withTestData =>
      if (withTestData) {
        import securesocial.core._
        val secretInfo = Oauth.hashClientSecret(SecretInfo("pass"))
        val client = Oauth2Client("DB_SERVICE", secretInfo, Seq("internal"), Seq("client_credentials"), "http://www.r.com/cb", Seq(), 3600, 3600, None, true)
        val client2 = Oauth2Client("WEB_APP", secretInfo, Seq("internal"), Seq("authorization_code", "implicit"), "http://www.r.com/cb", Seq("ROLE_USER"), 3600, 3600, None, false)
        Oauth.storeClient(client)
        Oauth.storeClient(client2)
        val user = securesocial.core.SocialUser(
          IdentityId("user@test.com", "userpass"),
          "Test",
          "User",
          "Test User",
          Some("user@test.com"),
          None,
          AuthenticationMethod.UserPassword,
          None,
          None,
          Some(Registry.hashers.get("bcrypt").get.hash("pass")))
        UserService.save(user)
      }
    }
  }
}