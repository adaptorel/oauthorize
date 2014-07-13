import play.Project._

name := "oauthorize-play-2.2"

version := "0.1"

organization := "com.oauthorize"

libraryDependencies ++= Seq(
  jdbc,
  anorm,
  cache,
  "ws.securesocial" %% "securesocial" % "2.1.3"
)     

javacOptions ++= Seq("-encoding", "UTF-8")

publishTo := {
  val localPublishRepo = "/Users/dorel/Work/_bitbucket_maven"
  if (version.value.trim.endsWith("SNAPSHOT")) 
    Some(Resolver.file("snapshots", new File(localPublishRepo + "/snapshots")))
  else
    Some(Resolver.file("releases", new File(localPublishRepo + "/releases")))
}

publishMavenStyle := true

play.Project.playScalaSettings

lazy val oauthorizePlay = project.in(file("."))
    .aggregate(oauthorize)
    .dependsOn(oauthorize)
    
lazy val oauthorize = project.in(file("zlibs/oauthorize"))    
