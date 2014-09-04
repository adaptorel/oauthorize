import play.Project._

name := "oauthorize-play-app"

version in ThisBuild := "0.3.3"

organization in ThisBuild := "com.oauthorize"

publishMavenStyle in ThisBuild := true

play.Project.playScalaSettings

lazy val main = project.in(file("."))
    .aggregate(oauthorizePlay)
    .dependsOn(oauthorizePlay)
lazy val oauthorizePlay = project.in(file("zlibs/oauthorize-play"))
    .aggregate(oauthorize)
    .dependsOn(oauthorize)
lazy val oauthorize = project.in(file("zlibs/oauthorize-core"))    
