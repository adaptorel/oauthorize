name := "oauthze"

version := "1.0-SNAPSHOT"

libraryDependencies ++= Seq(
  jdbc,
  anorm,
  cache,
  "ws.securesocial" %% "securesocial" % "2.1.3"
)     

play.Project.playScalaSettings
