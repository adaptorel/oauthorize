import play.Project._

name := "oauthorize-play-22x"

libraryDependencies ++= Seq(
  "securesocial" %% "securesocial" % "2.1.3.3-snmt"
)     

publishTo in ThisBuild := {
  val localPublishRepo = "/Users/dorel/Work/_bitbucket_maven"
  Some(Resolver.file("releases", new File(localPublishRepo)))
}

resolvers += "Oauthorize" at "https://bitbucket.org/dorel/maven/raw/master"

play.Project.playScalaSettings
