import play.api.Application
import play.api.mvc.WithFilters
import oauthorize.model.Oauth2Client
import app._

object Global extends Oauth2Filters {
  override def onStart(app: Application) = {
    app.configuration.getBoolean("with.test.data").map { withTestData =>
      if (withTestData) {
        import securesocial.core._
        val client = Oauth2Client("DB_SERVICE", Oauth.encodePassword("pass"), Seq("internal"), Seq("client_credentials"), "http://www.r.com/cb", Seq(), 3600, 3600, None, true)
        val client2 = Oauth2Client("WEB_APP", Oauth.encodePassword("pass"), Seq("internal"), Seq("authorization_code"), "http://www.r.com/cb", Seq("ROLE_USER"), 3600, 3600, None, true)
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