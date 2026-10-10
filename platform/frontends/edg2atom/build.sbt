name := "edg2atom"

dependsOn(
  Projects.c2cpg             % "compile->compile;test->test",
  Projects.dataflowengineoss % "compile->compile;test->test",
  Projects.x2cpg             % "compile->compile;test->test"
)

libraryDependencies ++= Seq(
  "com.lihaoyi"   %% "upickle"   % Versions.upickle,
  "org.scalatest" %% "scalatest" % Versions.scalatest % Test
)

Test / fork := true

githubOwner      := "appthreat"
githubRepository := "chen"
credentials +=
    Credentials(
      "GitHub Package Registry",
      "maven.pkg.github.com",
      "appthreat",
      sys.env.getOrElse("GITHUB_TOKEN", "N/A")
    )
