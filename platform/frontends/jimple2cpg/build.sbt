name := "jimple2cpg"

dependsOn(Projects.dataflowengineoss, Projects.x2cpg % "compile->compile;test->test")

libraryDependencies ++= Seq(
  "io.appthreat"  %% "cpg2" % Versions.cpg,
  "org.soot-oss"   % "soot"              % "4.4.1",
  "org.scala-lang.modules" % "scala-asm" % "9.6.0-scala-1",
  "org.ow2.asm"            % "asm"       % "9.6",
  "org.ow2.asm"            % "asm-analysis"       % "9.6",
  "org.ow2.asm"            % "asm-util"           % "9.6",
  "org.ow2.asm"            % "asm-tree"           % "9.6",
  "org.scalatest" %% "scalatest"         % Versions.scalatest % Test
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
