name := "c2cpg"

dependsOn(Projects.semanticcpg, Projects.dataflowengineoss % Test, Projects.x2cpg % "compile->compile;test->test")

libraryDependencies ++= Seq(
  "org.scala-lang.modules" %% "scala-parallel-collections" % "1.0.4",
  "org.eclipse.platform"    % "org.eclipse.equinox.common"       % "3.18.200",
  "org.eclipse.platform"    % "org.eclipse.core.resources"       % "3.20.0" excludeAll(
    ExclusionRule(organization = "com.ibm.icu", name = "icu4j"),
    ExclusionRule(organization = "org.eclipse.platform", name = "org.eclipse.jface"),
    ExclusionRule(organization = "org.eclipse.platform", name = "org.eclipse.jface.text")
  ),
  "org.jline"               % "jline"                      % "3.25.0",
  "org.scalatest"          %% "scalatest"                  % Versions.scalatest % Test
)

Compile / doc / scalacOptions ++= Seq("-doc-title", "semanticcpg apidocs", "-doc-version", version.value)

compile / javacOptions ++= Seq("-Xlint:all", "-Xlint:-cast", "-g")
Test / fork := true

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
