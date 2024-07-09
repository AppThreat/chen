package io.appthreat.jssrc2cpg

import Frontend.*
import io.appthreat.x2cpg.passes.frontend.{TypeRecoveryParserConfig, XTypeRecovery}
import io.appthreat.x2cpg.utils.Environment
import io.appthreat.x2cpg.{X2CpgConfig, X2CpgMain}
import scopt.OParser

import java.nio.file.Paths

final case class Config(tsTypes: Boolean = true) extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]:

  def withTsTypes(value: Boolean): Config =
      copy(tsTypes = value).withInheritedFields(this)

object Frontend:
  implicit val defaultConfig: Config = Config()

  val cmdLineParser: OParser[Unit, Config] =
    val builder = OParser.builder[Config]
    import builder.*
    OParser.sequence(
      programName("jssrc2cpg"),
      opt[Unit]("no-tsTypes")
          .hidden()
          .action((_, c) => c.withTsTypes(false))
          .text("disable generation of types via Typescript"),
      XTypeRecovery.parserOptions
    )

object Main extends X2CpgMain(cmdLineParser, new JsSrc2Cpg()):

  def run(config: Config, jssrc2cpg: JsSrc2Cpg): Unit =
    val absPath = Paths.get(config.inputPath).toAbsolutePath.toString
    if Environment.pathExists(absPath) then
      jssrc2cpg.run(config.withInputPath(absPath))
    else
      System.exit(1)
