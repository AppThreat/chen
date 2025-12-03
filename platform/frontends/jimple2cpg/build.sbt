name := "jimple2cpg"

dependsOn(Projects.dataflowengineoss, Projects.x2cpg % "compile->compile;test->test")

libraryDependencies ++= Seq(
  "io.appthreat"           %% "cpg2"              % Versions.cpg,
  "commons-io"             % "commons-io"         % "2.21.0",
  "org.soot-oss"           % "soot"               % "4.6.0",
  "org.scala-lang.modules" % "scala-asm"          % "9.9.0-scala-1",
  "org.ow2.asm"            % "asm"                % "9.9",
  "org.ow2.asm"            % "asm-analysis"       % "9.9",
  "org.ow2.asm"            % "asm-util"           % "9.9",
  "org.ow2.asm"            % "asm-tree"           % "9.9",
  "io.circe"               %% "circe-core"        % Versions.circe,
  "org.scalatest" %% "scalatest"                  % Versions.scalatest % Test
)

enablePlugins(JavaAppPackaging, LauncherJarPlugin)
trapExit    := false
Test / fork := true
githubOwner := "appthreat"
githubRepository := "chen"
credentials +=
  Credentials(
    "GitHub Package Registry",
    "maven.pkg.github.com",
    "appthreat",
    sys.env.getOrElse("GITHUB_TOKEN", "N/A")
  )
