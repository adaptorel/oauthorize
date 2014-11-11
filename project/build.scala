import sbt._, Keys._
import play.Project.{ filters, playScalaSettings }

object Build extends Build {
  lazy val allSettings = Seq(
    version := "0.2.10",
    organization := "com.oauthorize",
    scalaVersion := "2.10.4",
    publishMavenStyle := true,
    scalacOptions ++= Seq(
      "-feature",
      "-unchecked",
      "-deprecation",
      "-Yno-adapted-args",
      "-language:implicitConversions",
      "-language:higherKinds"
    )
  )

  lazy val root = Project(
    id = "oauthorize",
    base = file("."),
    aggregate = Seq(core, play, playExample),
    settings = allSettings
  )

  lazy val core = Project(
    id = "oauthorize-core",
    base = file("oauthorize-core"),
    settings = allSettings ++ Seq(
      libraryDependencies ++= Seq(
        "commons-codec" % "commons-codec"        % "1.9",
        "org.mindrot"   % "jbcrypt"              % "0.3m",
        "org.specs2"   %% "specs2-core"          % "2.3.12" % "test",
        "org.specs2"   %% "specs2-junit"         % "2.3.12" % "test",
        "org.specs2"   %% "specs2-mock"          % "2.3.12" % "test",
        "org.specs2"   %% "specs2-matcher-extra" % "2.3.12" % "test"
      )
    )
  )

  lazy val play = Project(
    id = "oauthorize-play-22x",
    base = file("oauthorize-play"),
    settings = playScalaSettings ++ allSettings ++ Seq(
      libraryDependencies ++= Seq(
        filters,
        "ws.securesocial" %% "securesocial" % "2.1.3"
      )
    )
  ).dependsOn(core)

  lazy val playExample = Project(
    id = "oauthorize-play-example",
    base = file("oauthorize-play-example"),
    settings = playScalaSettings ++ allSettings
  ).dependsOn(core)
   .dependsOn(play)
}