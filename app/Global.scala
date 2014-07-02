import play.api.GlobalSettings
import play.api.Application
import controllers.Application
import oauthze.model.OauthClient

object Global extends GlobalSettings {

  override def onStart(app: Application) = {
    val client = OauthClient("a", "a", Seq(), Seq("authorization_code"), "http://www.r.com/cb", Seq(), 3600, 3600, None, false)
    Application.saveClient(client)
  }

}