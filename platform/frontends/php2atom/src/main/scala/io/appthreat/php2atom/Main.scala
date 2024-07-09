package io.appthreat.php2atom

import io.appthreat.x2cpg.{X2CpgConfig, X2CpgMain}
import io.appthreat.x2cpg.passes.frontend.{TypeRecoveryParserConfig, XTypeRecovery}
import io.appthreat.php2atom.Frontend.*
import scopt.OParser

/** Command line configuration parameters
  */
final case class Config(phpIni: Option[String] = None, phpParserBin: Option[String] = None)
    extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]:
  def withPhpIni(phpIni: String): Config =
      copy(phpIni = Some(phpIni)).withInheritedFields(this)

  def withPhpParserBin(phpParserBin: String): Config =
      copy(phpParserBin = Some(phpParserBin)).withInheritedFields(this)

object Frontend:

  implicit val defaultConfig: Config = Config()

  val cmdLineParser: OParser[Unit, Config] =
    val builder = OParser.builder[Config]
    import builder.*
    OParser.sequence(
      programName("php2atom"),
      opt[String]("php-ini")
          .action((x, c) => c.withPhpIni(x))
          .text("php.ini path used by php-parser. Defaults to php.ini shipped with Chen."),
      opt[String]("php-parser-bin")
          .action((x, c) => c.withPhpParserBin(x))
          .text("path to php-parser.phar binary."),
      XTypeRecovery.parserOptions
    )

object Main extends X2CpgMain(cmdLineParser, new Php2Atom()):
  def run(config: Config, php2Cpg: Php2Atom): Unit =
      php2Cpg.run(config)
