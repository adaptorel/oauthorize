import play.Project._

name := "oauthorize-play-22x"

libraryDependencies ++= Seq(
  filters,
  "ws.securesocial" %% "securesocial" % "2.1.3"
)     

publishTo in ThisBuild := {
  val localPublishRepo = "/Users/dorel/Work/_bitbucket_maven"
  Some(Resolver.file("releases", new File(localPublishRepo)))
}

play.Project.playScalaSettings