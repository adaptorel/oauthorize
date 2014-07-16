name := "oauthorize-core"

val specsVersion = "2.3.12"

libraryDependencies ++= Seq(
  "commons-codec" % "commons-codec" % "1.9",
  "org.mindrot" % "jbcrypt" % "0.3m",
  "org.specs2" %% "specs2-core" % specsVersion % "test",
  "org.specs2" %% "specs2-junit" % specsVersion % "test",
  "org.specs2" %% "specs2-mock" % specsVersion % "test",
  "org.specs2" %% "specs2-matcher-extra" % specsVersion % "test"
  )