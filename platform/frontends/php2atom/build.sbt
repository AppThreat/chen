name := "php2atom"

dependsOn(Projects.dataflowengineoss, Projects.x2cpg % "compile->compile;test->test")

libraryDependencies ++= Seq(
  "com.lihaoyi"   %% "upickle"           % Versions.upickle,
  "com.lihaoyi"   %% "ujson"             % Versions.upickle,
  "io.shiftleft"  %% "codepropertygraph" % Versions.cpg,
  "org.scalatest" %% "scalatest"         % Versions.scalatest % Test,
  "io.circe"      %% "circe-core"        % Versions.circe
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
