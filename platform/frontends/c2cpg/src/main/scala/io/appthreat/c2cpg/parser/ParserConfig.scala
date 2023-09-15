package io.appthreat.c2cpg.parser

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.utils.IncludeAutoDiscovery

import java.nio.file.{Path, Paths}

object ParserConfig {

  def empty: ParserConfig =
    ParserConfig(
      Set.empty,
      Set.empty,
      Set.empty,
      Set.empty,
      Map.empty,
      Set.empty,
      logProblems = false,
      logPreprocessor = false
    )

  def fromConfig(config: Config): ParserConfig = ParserConfig(
    config.includeFiles.map(Paths.get(_).toAbsolutePath),
    config.includePaths.map(Paths.get(_).toAbsolutePath),
    IncludeAutoDiscovery.discoverIncludePathsC(config),
    IncludeAutoDiscovery.discoverIncludePathsCPP(config),
    config.defines.map {
      case define if define.contains("=") =>
        val s = define.split("=")
        s.head -> s(1)
      case define => define -> "true"
    }.toMap ++ DefaultDefines.DEFAULT_CALL_CONVENTIONS,
    config.macroFiles.map(Paths.get(_).toAbsolutePath),
    config.logProblems,
    config.logPreprocessor
  )

}

case class ParserConfig(
  includeFiles: Set[Path],
  userIncludePaths: Set[Path],
  systemIncludePathsC: Set[Path],
  systemIncludePathsCPP: Set[Path],
  definedSymbols: Map[String, String],
  macroFiles: Set[Path],
  logProblems: Boolean,
  logPreprocessor: Boolean
)
