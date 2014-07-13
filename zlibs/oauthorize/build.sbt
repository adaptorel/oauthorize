name := "oauthorize"

version := "0.1"

organization := "com.oauthorize"

val specsVersion = "2.3.12"

libraryDependencies ++= Seq(
  "commons-codec" % "commons-codec" % "1.9",
  "org.mindrot" % "jbcrypt" % "0.3m",
  "org.specs2" %% "specs2-core" % specsVersion % "test",
  "org.specs2" %% "specs2-junit" % specsVersion % "test",
  "org.specs2" %% "specs2-mock" % specsVersion % "test",
  "org.specs2" %% "specs2-matcher-extra" % specsVersion % "test"
  )

publishTo := {
  val localPublishRepo = "/Users/dorel/Work/_bitbucket_maven"
  if (version.value.trim.endsWith("SNAPSHOT")) 
    Some(Resolver.file("snapshots", new File(localPublishRepo + "/snapshots")))
  else
    Some(Resolver.file("releases", new File(localPublishRepo + "/releases")))
}

publishMavenStyle := true