name := "schema-extender"

ThisBuild / scalaVersion := "3.3.0"

val cpgVersion = IO.read(file("cpg-version"))

val generateDomainClasses = taskKey[Seq[File]]("generate overflowdb domain classes for our schema")

val joernInstallPath =
  settingKey[String]("path to joern installation, e.g. `/home/username/bin/joern/platform` or `../../joern/platform`")
joernInstallPath := "../"

val replaceDomainClassesInJoern =
  taskKey[Unit]("generates new domain classes based on the given schema, and installs them in the joern distribution")

replaceDomainClassesInJoern := {
  import java.nio.file._
  val newDomainClassesJar = (domainClasses / Compile / packageBin).value

  val targetFile =
    file(joernInstallPath.value) / "lib" / s"io.appthreat.codepropertygraph-domain-classes_3-$cpgVersion.jar"
  assert(targetFile.exists, s"target jar assumed to be $targetFile, but that file doesn't exist...")

  println(s"copying $newDomainClassesJar to $targetFile")
  Files.copy(newDomainClassesJar.toPath, targetFile.toPath, StandardCopyOption.REPLACE_EXISTING)
}

ThisBuild / libraryDependencies ++= Seq(
  "io.appthreat" %% "codepropertygraph-schema"         % cpgVersion,
  "io.appthreat" %% "codepropertygraph-domain-classes" % cpgVersion
)

lazy val schema = project
  .in(file("schema"))
  .settings(generateDomainClasses := {
    val outputRoot = target.value / "odb-codegen"
    FileUtils.deleteRecursively(outputRoot)
    val invoked = (Compile / runMain).toTask(s" CpgExtCodegen schema/target/odb-codegen").value
    FileUtils.listFilesRecursively(outputRoot)
  })

lazy val domainClasses =
  project.in(file("domain-classes")).settings(Compile / sourceGenerators += schema / generateDomainClasses)

Global / onChangedBuildSource := ReloadOnSourceChanges
