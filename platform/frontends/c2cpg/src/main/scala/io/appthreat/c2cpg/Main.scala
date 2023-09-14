package io.appthreat.c2cpg

import Frontend._
import io.appthreat.x2cpg.{X2CpgConfig, X2CpgMain}
import org.slf4j.LoggerFactory
import scopt.OParser

import scala.util.control.NonFatal

final case class Config(
  includePaths: Set[String] = Set.empty,
  defines: Set[String] = Set.empty,
  includeComments: Boolean = false,
  logProblems: Boolean = false,
  logPreprocessor: Boolean = false,
  printIfDefsOnly: Boolean = false,
  includePathsAutoDiscovery: Boolean = false,
  includeFunctionBodies: Boolean = false,
  includeImageLocations: Boolean = false,
  useProjectIndex: Boolean = true
) extends X2CpgConfig[Config] {
  def withIncludePaths(includePaths: Set[String]): Config = {
    this.copy(includePaths = includePaths).withInheritedFields(this)
  }

  def withDefines(defines: Set[String]): Config = {
    this.copy(defines = defines).withInheritedFields(this)
  }

  def withIncludeComments(value: Boolean): Config = {
    this.copy(includeComments = value).withInheritedFields(this)
  }

  def withLogProblems(value: Boolean): Config = {
    this.copy(logProblems = value).withInheritedFields(this)
  }

  def withLogPreprocessor(value: Boolean): Config = {
    this.copy(logPreprocessor = value).withInheritedFields(this)
  }

  def withPrintIfDefsOnly(value: Boolean): Config = {
    this.copy(printIfDefsOnly = value).withInheritedFields(this)
  }

  def withIncludePathsAutoDiscovery(value: Boolean): Config = {
    this.copy(includePathsAutoDiscovery = value).withInheritedFields(this)
  }

  def withFunctionBodies(value: Boolean): Config = {
    this.copy(includeFunctionBodies = value).withInheritedFields(this)
  }

  def withImageLocations(value: Boolean): Config = {
    this.copy(includeImageLocations = value).withInheritedFields(this)
  }

  def withProjectIndexes(value: Boolean): Config = {
    this.copy(useProjectIndex = value).withInheritedFields(this)
  }
}

private object Frontend {
  implicit val defaultConfig: Config = Config()

  val cmdLineParser: OParser[Unit, Config] = {
    val builder = OParser.builder[Config]
    import builder._
    OParser.sequence(
      programName(classOf[C2Cpg].getSimpleName),
      opt[Unit]("include-comments")
        .text(s"includes all comments into the CPG")
        .action((_, c) => c.withIncludeComments(true)),
      opt[Unit]("log-problems")
        .text(s"enables logging of all parse problems while generating the CPG")
        .action((_, c) => c.withLogProblems(true)),
      opt[Unit]("log-preprocessor")
        .text(s"enables logging of all preprocessor statements while generating the CPG")
        .action((_, c) => c.withLogPreprocessor(true)),
      opt[Unit]("print-ifdef-only")
        .text(s"prints a comma-separated list of all preprocessor ifdef and if statements; does not create a CPG")
        .action((_, c) => c.withPrintIfDefsOnly(true)),
      opt[String]("include")
        .unbounded()
        .text("header include paths")
        .action((incl, c) => c.withIncludePaths(c.includePaths + incl)),
      opt[Unit]("no-include-auto-discovery")
        .text("disables auto discovery of system header include paths")
        .hidden(),
      opt[Unit]("with-include-auto-discovery")
        .text("enables auto discovery of system header include paths")
        .action((_, c) => c.withIncludePathsAutoDiscovery(true)),
      opt[Unit]("with-function-bodies")
        .text("instructs the parser to parse function and method bodies.")
        .action((_, c) => c.withFunctionBodies(true)),
      opt[Unit]("with-image-locations")
        .text(
          "allows the parser to create image-locations. An image location explains how a name made it into the translation unit. Eg: via macro expansion or preprocessor."
        )
        .action((_, c) => c.withImageLocations(true)),
      opt[Unit]("with-project-index")
        .text("performance optimization, allows the parser to use an existing eclipse project(s) index(es).")
        .action((_, c) => c.withProjectIndexes(true)),
      opt[String]("define")
        .unbounded()
        .text("define a name")
        .action((d, c) => c.withDefines(c.defines + d))
    )
  }

}

object Main extends X2CpgMain(cmdLineParser, new C2Cpg()) {

  private val logger = LoggerFactory.getLogger(classOf[C2Cpg])

  def run(config: Config, c2cpg: C2Cpg): Unit = {
    if (config.printIfDefsOnly) {
      try {
        c2cpg.printIfDefsOnly(config)
      } catch {
        case NonFatal(ex) =>
          logger.error("Failed to print preprocessor statements.", ex)
          throw ex
      }
    } else {
      c2cpg.run(config)
    }
  }

}
