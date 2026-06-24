package io.appthreat.c2cpg.utils

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.FileDefaults
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

  // Directory names that never contain first-party project headers worth adding to the include
  // search path. Including them only inflates the path (every extra entry is probed for every
  // unresolved `#include`), so we prune them to keep header resolution fast.
  private val ExcludedDirNames: Set[String] = Set(
    "build",
    "cmake",
    "cmakefiles",
    "test",
    "tests",
    "testing",
    "node_modules",
    "third_party",
    "third-party",
    "thirdparty",
    "vendor",
    "examples",
    "docs",
    "doc"
  )

  /** Upper bound on the number of auto-discovered project include directories. Every entry is
    * probed for every unresolved `#include`, so an unbounded search path (aws-sdk-cpp discovers
    * ~450) makes `CPreprocessor.findInclusion` quadratic. Capping keeps resolution fast; the
    * shallowest (most general) include roots are kept first. Override via `CHEN_MAX_INCLUDE_PATHS`.
    */
  private val MaxProjectIncludePaths: Int =
      sys.env.get("CHEN_MAX_INCLUDE_PATHS").flatMap(s => Try(s.trim.toInt).toOption).filter(
        _ > 0
      ).getOrElse(50)

  private def isExcludedPath(p: Path): Boolean =
      p.iterator().asScala.exists { seg =>
        val name = seg.toString.toLowerCase
        name.startsWith(".") || ExcludedDirNames.contains(name)
      }

  /** True when `dir` contains at least one header file anywhere in its subtree. Uses a
    * short-circuit stream so it stops at the first match instead of materialising the whole
    * subtree.
    */
  private def containsHeaderFile(dir: Path): Boolean =
      Try {
          val stream = Files.walk(dir)
          try
              stream
                  .filter(Files.isRegularFile(_))
                  .anyMatch(p => FileDefaults.isHeaderFile(p.getFileName.toString))
          finally stream.close()
      }.getOrElse(true) // on error, keep the dir rather than risk dropping a valid include root

  def discoverProjectIncludePaths(rootPath: Path): Set[Path] =
    if !Files.exists(rootPath) || !Files.isDirectory(rootPath) then return Set.empty

    Try {
        val roots = Set(rootPath.toAbsolutePath)
        val candidateDirs = Files.walk(rootPath, 8)
            .filter(Files.isDirectory(_))
            .filter { p =>
              val name = p.getFileName.toString.toLowerCase
              (name.startsWith("include") || name == "headers" || name == "library") &&
              !isExcludedPath(p)
            }
            .map(_.toAbsolutePath)
            .collect(Collectors.toSet[Path])
            .asScala
            .toSet
        // Drop include directories that contain no header files anywhere beneath them. The walk
        // matches purely on directory name, so it picks up empty/irrelevant `include` dirs that
        // only add failed probes to CPreprocessor.findInclusion without ever resolving anything.
        val subDirs = candidateDirs.filter(containsHeaderFile)
        // Cap the search path: keep the project roots, then fill with the shallowest (most general)
        // include roots up to the limit. Shallow-first matches the probe order in CdtParser.
        val budget = Math.max(0, MaxProjectIncludePaths - roots.size)
        val cappedSubDirs = subDirs.toSeq
            .sortBy(p => (p.getNameCount, p.toString))
            .take(budget)
            .toSet
        roots ++ cappedSubDirs
    }.getOrElse(Set.empty)
  end discoverProjectIncludePaths

end IncludeAutoDiscovery
