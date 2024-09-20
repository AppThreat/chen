package io.appthreat.x2cpg.utils.dependency

import better.files.File
import io.appthreat.x2cpg.utils.ExternalCommand
import io.appthreat.x2cpg.utils.dependency.GradleConfigKeys.GradleConfigKey

import java.nio.file.Path
import scala.util.{Failure, Success}

object GradleConfigKeys extends Enumeration:
  type GradleConfigKey = Value
  val ProjectName, ConfigurationName = Value
case class DependencyResolverParams(
  forMaven: Map[String, String] = Map(),
  forGradle: Map[GradleConfigKey, String] = Map()
)

object DependencyResolver:
  private val MaxSearchDepth: Int = 4

  def getCoordinates(
    projectDir: Path,
    params: DependencyResolverParams = new DependencyResolverParams
  ): Option[collection.Seq[String]] =
    val coordinates = findSupportedBuildFiles(projectDir).flatMap { buildFile =>
        if isMavenBuildFile(buildFile) then
          // TODO: implement
          None
        else if isGradleBuildFile(buildFile) then
          Nil
        else
          Nil
    }.flatten

    Option.when(coordinates.nonEmpty)(coordinates)

  private def getCoordinatesForGradleProject(
    projectDir: Path,
    configuration: String
  ): Option[collection.Seq[String]] =
    val lines = ExternalCommand.run(
      s"gradle dependencies --configuration $configuration",
      projectDir.toString
    ) match
      case Success(lines) => lines
      case Failure(exception) =>
          Seq()

    val coordinates = MavenCoordinates.fromGradleOutput(lines)
    Some(coordinates)

  def getDependencies(
    projectDir: Path,
    params: DependencyResolverParams = new DependencyResolverParams
  ): Option[collection.Seq[String]] =
    val dependencies = findSupportedBuildFiles(projectDir).flatMap { buildFile =>
        if isMavenBuildFile(buildFile) then
          MavenDependencies.get(buildFile.getParent)
        else if isGradleBuildFile(buildFile) then
          Nil
        else
          Nil
    }.flatten

    Option.when(dependencies.nonEmpty)(dependencies)

  private def isGradleBuildFile(file: File): Boolean =
    val pathString = file.pathAsString
    pathString.endsWith(".gradle") || pathString.endsWith(".gradle.kts")

  private def isMavenBuildFile(file: File): Boolean =
      file.pathAsString.endsWith("pom.xml")

  private def findSupportedBuildFiles(currentDir: File, depth: Int = 0): List[Path] =
      if depth >= MaxSearchDepth then
        Nil
      else
        val (childDirectories, childFiles) = currentDir.children.partition(_.isDirectory)
        // Only fetch dependencies once for projects with both a build.gradle and a pom.xml file
        val childFileList = childFiles.toList
        childFileList
            .find(isGradleBuildFile)
            .orElse(childFileList.find(isMavenBuildFile)) match
          case Some(buildFile) => buildFile.path :: Nil

          case None if childDirectories.isEmpty => Nil

          case None =>
              childDirectories.flatMap { dir =>
                  findSupportedBuildFiles(dir, depth + 1)
              }.toList
end DependencyResolver
