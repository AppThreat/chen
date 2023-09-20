name := "console"

enablePlugins(JavaAppPackaging)

val ScoptVersion          = "4.1.0"
val CaskVersion           = "0.9.1"
val CirceVersion          = "0.14.5"
val ZeroturnaroundVersion = "1.15"

dependsOn(
  Projects.semanticcpg,
  Projects.macros,
  Projects.javasrc2cpg,
  Projects.jssrc2cpg,
  Projects.pysrc2cpg,
  Projects.x2cpg % "compile->compile;test->test"
)

libraryDependencies ++= Seq(
  "io.shiftleft"         %% "codepropertygraph" % Versions.cpg,
  "com.michaelpollmeier" %% "scala-repl-pp-server" % Versions.scalaReplPP,
  "com.github.scopt"     %% "scopt"             % ScoptVersion,
  "org.typelevel"        %% "cats-effect"       % Versions.cats,
  "io.circe"             %% "circe-generic"     % CirceVersion,
  "io.circe"             %% "circe-parser"      % CirceVersion,
  "org.zeroturnaround"    % "zt-zip"            % ZeroturnaroundVersion,
  "com.lihaoyi"          %% "os-lib"            % "0.9.1",
  "com.lihaoyi"          %% "pprint"            % "0.7.3",
  "com.lihaoyi"          %% "cask"              % CaskVersion,
  "me.shadaj"            %% "scalapy-core"      % "0.5.2",
  "org.scalatest"        %% "scalatest"         % Versions.scalatest % Test
)


Test / compile := (Test / compile).dependsOn((Projects.c2cpg / stage)).value

import ai.kien.python.Python

lazy val python = Python()

lazy val javaOpts = python.scalapyProperties.get.map {
  case (k, v) => s"""-D$k=$v"""
}.toSeq

javaOptions ++= javaOpts

githubOwner := "appthreat"
githubRepository := "chen"
credentials +=
  Credentials(
    "GitHub Package Registry",
    "maven.pkg.github.com",
    "appthreat",
    sys.env.getOrElse("GITHUB_TOKEN", "N/A")
  )
