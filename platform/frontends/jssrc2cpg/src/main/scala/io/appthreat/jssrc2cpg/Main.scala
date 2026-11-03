package io.appthreat.jssrc2cpg

import Frontend.*
import io.appthreat.x2cpg.passes.frontend.{TypeRecoveryParserConfig, XTypeRecovery}
import io.appthreat.x2cpg.utils.Environment
import io.appthreat.x2cpg.{X2CpgConfig, X2CpgMain}
import scopt.OParser

import java.nio.file.Paths

final case class Config(
  tsTypes: Boolean = true,
  flow: Boolean = false,
  astGenOutDir: Option[String] = None,
  astGenTypes: Option[String] = None
) extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]:

  def withTsTypes(value: Boolean): Config =
      copy(tsTypes = value).withInheritedFields(this)

  def withFlow(value: Boolean): Config =
      copy(flow = value).withInheritedFields(this)

  def withAstGenOutDir(value: String): Config =
      copy(astGenOutDir = Option(value)).withInheritedFields(this)

  /** Which engine astgen uses for type maps: `native` or `ts6`. Passed to astgen as ASTGEN_TYPES.
    * Unset leaves astgen's own default.
    */
  def withAstGenTypes(value: String): Config =
      copy(astGenTypes = Option(value).map(_.trim.toLowerCase).filter(_.nonEmpty))
          .withInheritedFields(this)

  /** The engine astgen is asked to use: the configured one, else ASTGEN_TYPES from the environment
    * astgen inherits (read the way astgen reads it, an unknown value means ts6), else ts6.
    */
  def effectiveAstGenTypes(env: Map[String, String] = sys.env): String =
      astGenTypes
          .orElse(env.get("ASTGEN_TYPES").map(_.trim.toLowerCase))
          .filter(Config.AstGenTypesValues.contains)
          .getOrElse("ts6")
end Config

object Config:
  val AstGenTypesValues: Seq[String] = Seq("native", "ts6")

object Frontend:
  implicit val defaultConfig: Config = Config()

  val cmdLineParser: OParser[Unit, Config] =
    val builder = OParser.builder[Config]
    import builder.*
    OParser.sequence(
      programName("jssrc2cpg"),
      opt[Unit]("no-tsTypes")
          .action((_, c) => c.withTsTypes(false))
          .text("disable generation of types via Typescript"),
      opt[Unit]("flow")
          .action((_, c) => c.withFlow(true))
          .text("enable flow mode (astgen -t flow)"),
      opt[String]("astgen-types")
          .validate(v =>
              if Config.AstGenTypesValues.contains(v.trim.toLowerCase) then Right(())
              else Left(s"astgen-types must be one of ${Config.AstGenTypesValues.mkString(", ")}")
          )
          .action((x, c) => c.withAstGenTypes(x))
          .text("type map engine for astgen: native or ts6 (sets ASTGEN_TYPES)"),
      opt[String]("astgen-out")
          .action((x, c) => c.withAstGenOutDir(x))
          .text("Configure a permanent directory for astgen output"),
      XTypeRecovery.parserOptions
    )
  end cmdLineParser
end Frontend

object Main extends X2CpgMain(cmdLineParser, new JsSrc2Cpg()):

  def run(config: Config, jssrc2cpg: JsSrc2Cpg): Unit =
    val absPath = Paths.get(config.inputPath).toAbsolutePath.toString
    if Environment.pathExists(absPath) then
      jssrc2cpg.run(config.withInputPath(absPath))
    else
      System.exit(1)
