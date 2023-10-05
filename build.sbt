name                     := "chen"
ThisBuild / organization := "io.appthreat"
ThisBuild / version      := "0.0.12"
ThisBuild / scalaVersion := "3.3.1"

val cpgVersion = "1.4.22"

lazy val platform          = Projects.platform
lazy val console           = Projects.console
lazy val dataflowengineoss = Projects.dataflowengineoss
lazy val macros            = Projects.macros
lazy val semanticcpg       = Projects.semanticcpg
lazy val c2cpg             = Projects.c2cpg
lazy val x2cpg             = Projects.x2cpg
lazy val pysrc2cpg         = Projects.pysrc2cpg
lazy val jssrc2cpg         = Projects.jssrc2cpg
lazy val javasrc2cpg       = Projects.javasrc2cpg
lazy val jimple2cpg        = Projects.jimple2cpg

lazy val aggregatedProjects: Seq[ProjectReference] = Seq(
  platform,
  console,
  dataflowengineoss,
  macros,
  semanticcpg,
  c2cpg,
  x2cpg,
  pysrc2cpg,
  jssrc2cpg,
  javasrc2cpg,
  jimple2cpg,
)

ThisBuild / libraryDependencies ++= Seq(
  "org.slf4j"                % "slf4j-api"         % "2.0.7",
  "org.apache.logging.log4j" % "log4j-slf4j2-impl" % "2.20.0" % Optional,
  "org.apache.logging.log4j" % "log4j-core"        % "2.20.0" % Optional
  // `Optional` means "not transitive", but still included in "stage/lib"
)

ThisBuild / compile / javacOptions ++= Seq(
  "-g", // debug symbols
  "-Xlint",
  "--release=17"
) ++ {
  // fail early if users with JDK8 try to run this
  val javaVersion = sys.props("java.specification.version").toFloat
  assert(javaVersion.toInt >= 17, s"this build requires JDK17+ - you're using $javaVersion")
  Nil
}

ThisBuild / scalacOptions ++= Seq(
  "-deprecation", // Emit warning and location for usages of deprecated APIs.
  "--release",
  "17",
)


enablePlugins(JavaAppPackaging, ClasspathJarPlugin)

lazy val createDistribution = taskKey[File]("Create a complete chen distribution")
createDistribution := {
  val distributionFile = file("target/chen.zip")
  val zip              = (platform / Universal / packageBin).value
  IO.copyFile(zip, distributionFile)
  println(s"created distribution - resulting files: $distributionFile")
  distributionFile
}

ThisBuild / resolvers ++= Seq(
  Resolver.mavenLocal,
  "Sonatype OSS" at "https://oss.sonatype.org/content/repositories/public",
  "Atlassian" at "https://packages.atlassian.com/mvn/maven-atlassian-external",
  "Gradle Releases" at "https://repo.gradle.org/gradle/libs-releases/"
)

ThisBuild / assemblyMergeStrategy := {
  case PathList("javax", "servlet", xs @ _*)         => MergeStrategy.first
  case PathList(ps @ _*) if ps.last endsWith ".html" => MergeStrategy.first
  case "application.conf"                            => MergeStrategy.concat
  case "unwanted.txt"                                => MergeStrategy.discard
  case x => MergeStrategy.preferProject
}

ThisBuild / versionScheme := Some("early-semver")

ThisBuild / Test / fork := true
Global / onChangedBuildSource := ReloadOnSourceChanges

publish / skip := true // don't publish the root project

// Avoids running root tasks on the benchmarks project
lazy val root = project
  .in(file("."))
  .aggregate(aggregatedProjects*)

ThisBuild / Test / packageBin / publishArtifact := true
