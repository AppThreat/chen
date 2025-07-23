import scala.sys.process.stringToProcess
import scala.util.Try
import versionsort.VersionHelper
import com.typesafe.config.{Config, ConfigFactory}

name := "jssrc2cpg"

dependsOn(Projects.dataflowengineoss, Projects.x2cpg % "compile->compile;test->test")

libraryDependencies ++= Seq(
  "io.appthreat"              %% "cpg2" % Versions.cpg,
  "com.lihaoyi"               %% "upickle"           % Versions.upickle,
  "com.typesafe"               % "config"            % "1.4.4",
  "com.michaelpollmeier"       % "versionsort"       % "1.0.17",
  "org.scalatest"             %% "scalatest"         % Versions.scalatest % Test
)

Compile / doc / scalacOptions ++= Seq("-doc-title", "semanticcpg apidocs", "-doc-version", version.value)

compile / javacOptions ++= Seq("-Xlint:all", "-Xlint:-cast", "-g")
Test / fork := false

enablePlugins(JavaAppPackaging, LauncherJarPlugin)

Universal / packageName       := name.value
Universal / topLevelDirectory := None
githubOwner := "appthreat"
githubRepository := "chen"
credentials +=
  Credentials(
    "GitHub Package Registry",
    "maven.pkg.github.com",
    "appthreat",
    sys.env.getOrElse("GITHUB_TOKEN", "N/A")
  )
