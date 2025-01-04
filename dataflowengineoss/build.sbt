name := "dataflowengineoss"

dependsOn(Projects.semanticcpg, Projects.x2cpg)

libraryDependencies ++= Seq(
  "org.antlr"               % "antlr4-runtime"             % Versions.antlr,
  "io.circe"               %% "circe-core"                 % Versions.circe,
  "io.circe"               %% "circe-generic"              % Versions.circe,
  "io.circe"               %% "circe-parser"               % Versions.circe,
  "org.scalatest"          %% "scalatest"                  % Versions.scalatest % Test,
  "org.scala-lang.modules" %% "scala-parallel-collections" % "1.1.0"
)

enablePlugins(Antlr4Plugin)

Antlr4 / antlr4PackageName := Some("io.appthreat.dataflowengineoss")
Antlr4 / antlr4Version     := Versions.antlr
Antlr4 / javaSource        := (Compile / sourceManaged).value
Compile / doc / sources ~= (_ filter (_ => false))
githubOwner := "appthreat"
githubRepository := "chen"
credentials +=
  Credentials(
    "GitHub Package Registry",
    "maven.pkg.github.com",
    "appthreat",
    sys.env.getOrElse("GITHUB_TOKEN", "N/A")
  )
