name := "x2cpg"

dependsOn(Projects.semanticcpg)

libraryDependencies ++= Seq(
  "io.circe" %% "circe-core" % Versions.circe,
  "io.circe" %% "circe-generic" % Versions.circe,
  "io.circe" %% "circe-parser" % Versions.circe,
  "org.scalatest" %% "scalatest"          % Versions.scalatest     % Test
)

Compile / doc / scalacOptions ++= Seq("-doc-title", "semanticcpg apidocs", "-doc-version", version.value)

compile / javacOptions ++= Seq("-Xlint:all", "-Xlint:-cast", "-g")
Test / fork := true

enablePlugins(JavaAppPackaging)

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
