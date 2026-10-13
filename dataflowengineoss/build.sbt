name := "dataflowengineoss"

BareBuildSyntax.dependsOn(Projects.semanticcpg, Projects.x2cpg)

libraryDependencies ++= Seq(
  "org.antlr"               % "antlr4-runtime"             % Versions.antlr,
  "io.circe"               %% "circe-core"                 % Versions.circe,
  "io.circe"               %% "circe-generic"              % Versions.circe,
  "io.circe"               %% "circe-parser"               % Versions.circe,
  "org.scalatest"          %% "scalatest"                  % Versions.scalatest % Test,
  "org.scala-lang.modules" %% "scala-parallel-collections" % Versions.scalaParallel
)

Compile / sourceGenerators += Antlr4.sourceGenerator("io.appthreat.dataflowengineoss").taskValue
Compile / doc / sources ~= (_.filter(_ => false))
githubOwner      := "appthreat"
githubRepository := "chen"
credentials +=
    Credentials(
      "GitHub Package Registry",
      "maven.pkg.github.com",
      "appthreat",
      sys.env.getOrElse("GITHUB_TOKEN", "N/A")
    )
