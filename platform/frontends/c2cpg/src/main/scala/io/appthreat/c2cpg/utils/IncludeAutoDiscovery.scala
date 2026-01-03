package io.appthreat.c2cpg.utils

import io.appthreat.c2cpg.Config
import org.slf4j.LoggerFactory

import java.nio.file.{Files, Path, Paths}
import java.util.stream.Collectors
import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try}

object IncludeAutoDiscovery:

  private val logger = LoggerFactory.getLogger(IncludeAutoDiscovery.getClass)

  private val IS_WIN = scala.util.Properties.isWin

  val GCC_VERSION_COMMAND = "gcc --version"
  private val GCC_CPP_INCLUDE_COMMAND =
      if IS_WIN then "gcc -xc++ -E -v . -o nul" else "gcc -xc++ -E -v /dev/null -o /dev/null"
  private val GCC_C_INCLUDE_COMMAND =
      if IS_WIN then "gcc -xc -E -v . -o nul" else "gcc -xc -E -v /dev/null -o /dev/null"

  val CLANG_VERSION_COMMAND = "clang --version"
  private val CLANG_CPP_INCLUDE_COMMAND =
      if IS_WIN then "clang -xc++ -E -v . -o nul" else "clang -xc++ -E -v /dev/null -o /dev/null"
  private val CLANG_C_INCLUDE_COMMAND =
      if IS_WIN then "clang -xc -E -v . -o nul" else "clang -xc -E -v /dev/null -o /dev/null"

  private var isGccAvailable: Option[Boolean]      = None
  private var systemIncludePathsC_GCC: Set[Path]   = Set.empty
  private var systemIncludePathsCPP_GCC: Set[Path] = Set.empty

  private var isClangAvailable: Option[Boolean]      = None
  private var systemIncludePathsC_Clang: Set[Path]   = Set.empty
  private var systemIncludePathsCPP_Clang: Set[Path] = Set.empty

  private def checkForGcc(): Boolean =
      ExternalCommand.run(GCC_VERSION_COMMAND) match
        case Success(result) =>
            logger.debug(s"GCC is available: ${result.mkString(System.lineSeparator())}")
            true
        case _ =>
            logger.warn(
              "GCC is not installed. Discovery of system include paths will not be available."
            )
            false

  def gccAvailable(): Boolean = isGccAvailable match
    case Some(value) => value
    case None =>
        isGccAvailable = Option(checkForGcc())
        isGccAvailable.get

  private def extractPaths(output: Seq[String]): Set[Path] =
    val startIndex = output.indexWhere(_.contains("#include <...> search starts here:"))
    if startIndex == -1 then
      logger.warn("Could not find start marker for include paths in compiler output.")
      return Set.empty
    val endIndex = output.indexWhere(_.startsWith("End of search list."), startIndex + 1)
    if endIndex == -1 then
      logger.warn("Could not find end marker for include paths in compiler output.")
      return Set.empty
    output.slice(startIndex + 1, endIndex)
        .map(_.trim)
        .filter(_.nonEmpty)
        .map(p => Paths.get(p).toAbsolutePath)
        .toSet

  private def discoverPathsGCC(command: String): Set[Path] = ExternalCommand.run(command) match
    case Success(output) => extractPaths(output)
    case Failure(exception) =>
        logger.warn(
          s"Unable to discover system include paths with GCC. Running '$command' failed.",
          exception
        )
        Set.empty

  private def checkForClang(): Boolean =
      ExternalCommand.run(CLANG_VERSION_COMMAND) match
        case Success(result) =>
            logger.debug(s"Clang is available: ${result.mkString(System.lineSeparator())}")
            true
        case _ =>
            logger.warn(
              "Clang is not installed. Discovery of system include paths will not be available."
            )
            false

  private def isClangAvailableCheck(): Boolean = isClangAvailable match
    case Some(value) => value
    case None =>
        isClangAvailable = Option(checkForClang())
        isClangAvailable.get

  private def discoverPathsClang(command: String): Set[Path] = ExternalCommand.run(command) match
    case Success(output) => extractPaths(output)
    case Failure(exception) =>
        logger.warn(
          s"Unable to discover system include paths with Clang. Running '$command' failed.",
          exception
        )
        Set.empty

  def discoverIncludePathsC_GCC(config: Config): Set[Path] =
      if config.includePathsAutoDiscovery && systemIncludePathsC_GCC.nonEmpty then
        systemIncludePathsC_GCC
      else if config.includePathsAutoDiscovery && systemIncludePathsC_GCC.isEmpty && gccAvailable()
      then
        val includePathsC = discoverPathsGCC(GCC_C_INCLUDE_COMMAND)
        if includePathsC.nonEmpty then
          logger.debug(
            s"Using the following GCC C system include paths:${includePathsC
                    .mkString(s"${System.lineSeparator()}- ", s"${System.lineSeparator()}- ", System.lineSeparator())}"
          )
        systemIncludePathsC_GCC = includePathsC
        includePathsC
      else
        Set.empty

  def discoverIncludePathsCPP_GCC(config: Config): Set[Path] =
      if config.includePathsAutoDiscovery && systemIncludePathsCPP_GCC.nonEmpty then
        systemIncludePathsCPP_GCC
      else if config.includePathsAutoDiscovery && systemIncludePathsCPP_GCC.isEmpty && gccAvailable()
      then
        val includePathsCPP = discoverPathsGCC(GCC_CPP_INCLUDE_COMMAND)
        if includePathsCPP.nonEmpty then
          logger.debug(
            s"Using the following GCC CPP system include paths:${includePathsCPP
                    .mkString(s"${System.lineSeparator()}- ", s"${System.lineSeparator()}- ", System.lineSeparator())}"
          )
        systemIncludePathsCPP_GCC = includePathsCPP
        includePathsCPP
      else
        Set.empty

  def discoverIncludePathsC_Clang(config: Config): Set[Path] =
      if config.includePathsAutoDiscovery && systemIncludePathsC_Clang.nonEmpty then
        systemIncludePathsC_Clang
      else if config.includePathsAutoDiscovery && systemIncludePathsC_Clang
            .isEmpty && isClangAvailableCheck()
      then
        val includePathsC = discoverPathsClang(CLANG_C_INCLUDE_COMMAND)
        if includePathsC.nonEmpty then
          logger.debug(
            s"Using the following Clang C system include paths:${includePathsC
                    .mkString(s"${System.lineSeparator()}- ", s"${System.lineSeparator()}- ", System.lineSeparator())}"
          )
        systemIncludePathsC_Clang = includePathsC
        includePathsC
      else
        Set.empty

  def discoverIncludePathsCPP_Clang(config: Config): Set[Path] =
      if config.includePathsAutoDiscovery && systemIncludePathsCPP_Clang.nonEmpty then
        systemIncludePathsCPP_Clang
      else if config.includePathsAutoDiscovery && systemIncludePathsCPP_Clang
            .isEmpty && isClangAvailableCheck()
      then
        val includePathsCPP = discoverPathsClang(CLANG_CPP_INCLUDE_COMMAND)
        if includePathsCPP.nonEmpty then
          logger.debug(
            s"Using the following Clang CPP system include paths:${includePathsCPP
                    .mkString(s"${System.lineSeparator()}- ", s"${System.lineSeparator()}- ", System.lineSeparator())}"
          )
        systemIncludePathsCPP_Clang = includePathsCPP
        includePathsCPP
      else
        Set.empty

  def discoverIncludePathsC(config: Config): Set[Path] =
      discoverIncludePathsC_GCC(config) ++ discoverIncludePathsC_Clang(config)

  def discoverIncludePathsCPP(config: Config): Set[Path] =
      discoverIncludePathsCPP_GCC(config) ++ discoverIncludePathsCPP_Clang(config)

  def discoverProjectIncludePaths(rootPath: Path): Set[Path] =
    if !Files.exists(rootPath) || !Files.isDirectory(rootPath) then return Set.empty

    Try {
        val roots = Set(rootPath.toAbsolutePath)
        val subDirs = Files.walk(rootPath, 8)
            .filter(Files.isDirectory(_))
            .filter { p =>
              val name = p.getFileName.toString.toLowerCase
              name == "include" || name == "includes" || name == "src" || name == "headers" || name == "third_party"
            }
            .map(_.toAbsolutePath)
            .collect(Collectors.toSet[Path])
            .asScala
            .toSet
        roots ++ subDirs
    }.getOrElse(Set.empty)

end IncludeAutoDiscovery
