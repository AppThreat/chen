name := "platform"

dependsOn(Projects.console, Projects.console % "test->test", Projects.dataflowengineoss, Projects.x2cpg)

libraryDependencies ++= Seq(
  "io.appthreat"     %% "cpg2" % Versions.cpg,
  "com.lihaoyi"      %% "requests"          % Versions.requests,
  "com.github.scopt" %% "scopt"             % "4.1.0",
  "org.reflections"   % "reflections"       % "0.10.2",
  "org.scalatest"    %% "scalatest"         % Versions.scalatest % Test
)

Test / compile := (Test / compile).dependsOn((Projects.c2cpg / stage), (Projects.jssrc2cpg / stage)).value
Test / fork    := false

enablePlugins(JavaAppPackaging, UniversalPlugin)

//wildcard import from staged `lib` dir, for simplicity and also to avoid `line too long` error on windows
scriptClasspath := Seq("*")

topLevelDirectory := Some(packageName.value)

Compile / packageDoc / mappings := Seq()

def frontendMappings(frontendName: String, stagedProject: File): Seq[(File, String)] = {
  NativePackagerHelper.contentOf(stagedProject).map { case (file, name) =>
    file -> s"frontends/$frontendName/$name"
  }
}

lazy val x2cpg       = project.in(file("frontends/x2cpg"))
lazy val javasrc2cpg = project.in(file("frontends/javasrc2cpg"))
lazy val pysrc2cpg   = project.in(file("frontends/pysrc2cpg"))
lazy val jimple2cpg  = project.in(file("frontends/jimple2cpg"))
lazy val jssrc2cpg   = project.in(file("frontends/jssrc2cpg"))

Universal / mappings ++= frontendMappings("javasrc2cpg", (javasrc2cpg / stage).value)
Universal / mappings ++= frontendMappings("c2cpg", (Projects.c2cpg / stage).value)
Universal / mappings ++= frontendMappings("jssrc2cpg", (jssrc2cpg / stage).value)
Universal / mappings ++= frontendMappings("jimple2cpg", (jimple2cpg / stage).value)
Universal / mappings ++= frontendMappings("pysrc2cpg", (pysrc2cpg / stage).value)

lazy val cpgVersionFile = taskKey[File]("persist cpg version in file (e.g. for schema-extender)")
cpgVersionFile := {
  val ret = target.value / "cpg-version"
  better.files
    .File(ret.getPath)
    .createIfNotExists(createParents = true)
    .writeText(Versions.cpg)
  ret
}
Universal / mappings += cpgVersionFile.value -> "schema-extender/cpg-version"

lazy val generateScaladocs = taskKey[File]("generate scaladocs from combined project sources")
generateScaladocs := {
  import better.files.*
  import java.io.{File => JFile, PrintWriter}
  import sbt.internal.inc.AnalyzingCompiler
  import sbt.internal.util.Attributed.data
  import net.lingala.zip4j.ZipFile
  import sbt.internal.CommandStrings.ExportStream

  val updateReport = updateClassifiers.value
  val label        = "Chen API documentation"
  val s            = streams.value
  val out          = target.value / "api"
  val fiOpts       = (Compile / doc / fileInputOptions).value

  val sOpts = Seq("-language:implicitConversions", "-doc-root-content", "api-doc-root.txt", "-implicits")

  val xapis   = apiMappings.value
  val options = sOpts ++ Opts.doc.externalAPI(xapis)
  val cp      = data((Compile / dependencyClasspath).value).toList

  val inputFilesRelativeDir = target.value + "/inputFiles"
  val inputFiles            = File(inputFilesRelativeDir)
  if (inputFiles.exists) inputFiles.delete()
  inputFiles.createDirectory()

  /* extract sources-jar dependencies */
  List("cpg2", "semanticcpg").foreach { projectName =>
    val jar = SbtHelper.findJar(s"${projectName}_3", updateReport, SbtHelper.JarClassifier.Sources)
    new ZipFile(jar).extractAll(inputFiles.pathAsString)
  }

  // slightly adapted from sbt's Default.scala `docTaskSettings`
  val srcs: Seq[JFile] =
    inputFiles.listRecursively
      .filter { file =>
        file.extension.contains(".java") || file.extension.contains(".scala")
      }
      .map(_.toJava)
      .toSeq

  def exportedPW(w: PrintWriter, command: String): Seq[String] => Unit =
    args => w.println((command +: args).mkString(" "))

  def exportedTS(s: TaskStreams, command: String): Seq[String] => Unit = args => {
    val w = s.text(ExportStream)
    try exportedPW(w, command)
    finally w.close()
  }

  val runDoc = Doc.scaladoc(
    label,
    s.cacheStoreFactory.sub("scala"),
    compilers.value.scalac match {
      case ac: AnalyzingCompiler => ac.onArgs(exportedTS(s, "scaladoc"))
    },
    fiOpts
  )

  runDoc(srcs, cp, out, options, maxErrors.value, s.log)

  out
}

Universal / packageBin / mappings ++= sbt.Path.directory(new File("platform/src/main/resources/scripts"))

maintainer := "cloud@appthreat.com"
githubOwner := "appthreat"
githubRepository := "chen"
credentials +=
  Credentials(
    "GitHub Package Registry",
    "maven.pkg.github.com",
    "appthreat",
    sys.env.getOrElse("GITHUB_TOKEN", "N/A")
  )
