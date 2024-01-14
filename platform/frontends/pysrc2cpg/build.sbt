name := "pysrc2cpg"

dependsOn(Projects.dataflowengineoss, Projects.x2cpg % "compile->compile;test->test")

libraryDependencies ++= Seq(
  "io.appthreat"           %% "cpg2"          % Versions.cpg,
  "org.scala-lang.modules" %% "scala-parallel-collections" % "1.0.4",
  "org.scalatest"          %% "scalatest"                  % Versions.scalatest % Test
)

enablePlugins(JavaAppPackaging, LauncherJarPlugin)
trapExit                      := false
Global / onChangedBuildSource := ReloadOnSourceChanges

val javaCCTask = taskKey[Seq[File]]("Generate compiler code with JavaCC")
javaCCTask / fileInputs += baseDirectory.value.toGlob / "pythonGrammar.jj"
javaCCTask := {
  import org.javacc.parser.{Main => JavaCCMain}
  val outputDir       = (Compile / sourceManaged).value / "io" / "appthreat" / "pythonparser"
  val inputFileOption = javaCCTask.inputFiles.head
  if (
    !outputDir.exists() ||
    javaCCTask.inputFileChanges.created.nonEmpty ||
    javaCCTask.inputFileChanges.modified.nonEmpty
  ) JavaCCMain.mainProgram(Array(s"-OUTPUT_DIRECTORY=$outputDir", inputFileOption.toString))
  os.walk(os.Path(outputDir)).filter(path => os.isFile(path) && path.ext == "java").map(_.toIO)
}

Compile / sourceGenerators += javaCCTask
githubOwner := "appthreat"
githubRepository := "chen"
credentials +=
  Credentials(
    "GitHub Package Registry",
    "maven.pkg.github.com",
    "appthreat",
    sys.env.getOrElse("GITHUB_TOKEN", "N/A")
  )
