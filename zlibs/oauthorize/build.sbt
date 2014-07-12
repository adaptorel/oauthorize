name := "oauthorize"

version := "0.1"

organization := "com.oauthorize"

libraryDependencies += "commons-codec" % "commons-codec" % "1.9"

publishTo := {
  val localPublishRepo = "/Users/dorel/Work/_bitbucket_maven"
  if (version.value.trim.endsWith("SNAPSHOT")) 
    Some(Resolver.file("snapshots", new File(localPublishRepo + "/snapshots")))
  else
    Some(Resolver.file("releases", new File(localPublishRepo + "/releases")))
}

publishMavenStyle := true