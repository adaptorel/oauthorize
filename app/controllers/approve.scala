package controllers

import play.api._
import play.api.mvc._
import oauthze.model._
import oauth2.spec.Error._
import oauth2.spec.AuthzErrors._
import oauth2.spec.Req._
import oauthze.service.OauthClientStore

trait UserApproval extends Controller {

  this: OauthClientStore =>

  private[controllers] def initiateApproval(authzCode: String, authzRequest: AuthzRequest, client: Oauth2Client) =
    Ok(views.html.user_approval(authzCode, authzRequest, client))

  private[controllers] def approved(authzCode: String, maybeState: Option[String], client: Oauth2Client) = {
    val temp = Map(code -> Seq(authzCode))
    val params = maybeState.map(s => temp + (state -> Seq(s))).getOrElse(temp)
    Redirect(s"${client.redirectUri}", params, 302)
  }

  def processApprove = Action { implicit request =>
    import frm._
    ApproveModelForm.bindFromRequest.fold(
      formWithErrors => { println(formWithErrors.errorsAsJson); InternalServerError },
      model => {
        //TODO srsly, .get?
        val authzCode = model.code.get
        val authzRequest = getAuthzRequest(authzCode).get
        val client = getClient(authzRequest.clientId).get
        val isApproved = model.allow.map(_ == "approve").getOrElse(false)
        if (isApproved)
          approved(authzCode, model.state, client)
        else {
          val temp = Map(error -> Seq(access_denied))
          val params = request.getQueryString(state).map(s => temp + (state -> Seq(s))).getOrElse(temp)
          Redirect(s"${client.redirectUri}", params, 302)
        }
      })
  }

  object frm {
    import play.api.data._
    import play.api.data.Forms._
    case class ApproveModel(code: Option[String], state: Option[String], allow: Option[String], deny: Option[String])
    val ApproveModelForm = Form(
      mapping(
        "code" -> optional(text),
        "state" -> optional(text),
        "Allow" -> optional(text),
        "Deny" -> optional(text))(ApproveModel.apply)(ApproveModel.unapply))
  }

}