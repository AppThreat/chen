name := "ruby2atom"

dependsOn(Projects.dataflowengineoss % "compile->compile;test->test", Projects.x2cpg % "compile->compile;test->test")

libraryDependencies ++= Seq(
  "io.appthreat"   %% "cpg2"           % Versions.cpg,
  "com.lihaoyi"    %% "upickle"        % Versions.upickle,
  "org.scalatest"  %% "scalatest"      % Versions.scalatest % Test
)

enablePlugins(JavaAppPackaging, LauncherJarPlugin)
Global / onChangedBuildSource := ReloadOnSourceChanges
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
