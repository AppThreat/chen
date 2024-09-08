name := "console"

enablePlugins(JavaAppPackaging)

val ScoptVersion          = "4.1.0"
val CaskVersion           = "0.9.4"
val CirceVersion          = "0.14.10"
val ZeroturnaroundVersion = "1.17"

dependsOn(
  Projects.semanticcpg,
  Projects.macros,
  Projects.javasrc2cpg,
  Projects.jssrc2cpg,
  Projects.pysrc2cpg,
  Projects.x2cpg % "compile->compile;test->test"
)

libraryDependencies ++= Seq(
  "io.appthreat"         %% "cpg2" % Versions.cpg,
  "com.michaelpollmeier" %% "scala-repl-pp-server" % Versions.scalaReplPP,
  "com.github.scopt"     %% "scopt"             % ScoptVersion,
  "org.typelevel"        %% "cats-effect"       % Versions.cats,
  "io.circe"             %% "circe-generic"     % CirceVersion,
  "io.circe"             %% "circe-parser"      % CirceVersion,
  "org.zeroturnaround"    % "zt-zip"            % ZeroturnaroundVersion,
  "com.lihaoyi"          %% "os-lib"            % "0.10.6",
  "com.lihaoyi"          %% "pprint"            % "0.9.0",
  "com.lihaoyi"          %% "cask"              % CaskVersion,
  "dev.scalapy"          %% "scalapy-core"      % "0.5.3",
  "org.scala-lang.modules" % "scala-asm"        % "9.7.0-scala-2",
  "org.scalatest"        %% "scalatest"         % Versions.scalatest % Test,
  "org.scala-lang"       %% "scala3-compiler"   % "3.5.0"
)


Test / compile := (Test / compile).dependsOn((Projects.c2cpg / stage)).value

import ai.kien.python.Python

lazy val python = Python()

lazy val javaOpts = python.scalapyProperties.get.map {
  case (k, v) => s"""-D$k=$v"""
}.toSeq

javaOptions ++= (if (javaOpts.isEmpty && System.getenv("Python3_ROOT_DIR").nonEmpty) Seq("-Djna.library.path=" + System.getenv("Python3_ROOT_DIR")) else javaOpts)


githubOwner := "appthreat"
githubRepository := "chen"
credentials +=
  Credentials(
    "GitHub Package Registry",
    "maven.pkg.github.com",
    "appthreat",
    sys.env.getOrElse("GITHUB_TOKEN", "N/A")
  )
