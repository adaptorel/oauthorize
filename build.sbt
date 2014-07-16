import play.Project._

name := "oauthorize-play-22x"

version in ThisBuild := "0.1"

organization in ThisBuild := "com.oauthorize"

libraryDependencies ++= Seq(
  "ws.securesocial" %% "securesocial" % "2.1.3"
)     

publishTo in ThisBuild := {
  val localPublishRepo = "/Users/dorel/Work/_bitbucket_maven"
  Some(Resolver.file("releases", new File(localPublishRepo)))
}

publishMavenStyle in ThisBuild := true

play.Project.playScalaSettings

lazy val oauthorizePlay = project.in(file("."))
    .aggregate(oauthorize)
    .dependsOn(oauthorize)
    
lazy val oauthorize = project.in(file("zlibs/oauthorize"))    