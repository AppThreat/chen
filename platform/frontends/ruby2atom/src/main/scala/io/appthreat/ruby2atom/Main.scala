package io.appthreat.ruby2atom

import io.appthreat.ruby2atom.Frontend.*
import io.appthreat.x2cpg.astgen.AstGenConfig
import io.appthreat.x2cpg.passes.frontend.{
    TypeRecoveryParserConfig,
    XTypeRecovery,
    XTypeRecoveryConfig
}
import io.appthreat.x2cpg.typestub.TypeStubConfig
import io.appthreat.x2cpg.{X2CpgConfig, X2CpgMain}
import scopt.OParser

import java.nio.file.Paths

final case class Config(downloadDependencies: Boolean = false, useTypeStubs: Boolean = true)
    extends X2CpgConfig[Config]
    with TypeRecoveryParserConfig[Config]
    with TypeStubConfig[Config]
    with AstGenConfig[Config]:

  override val astGenProgramName: String        = "ruby_ast_gen"
  override val astGenConfigPrefix: String       = "ruby2atom"
  override val multiArchitectureBuilds: Boolean = true

  this.defaultIgnoredFilesRegex =
      List("spec", "tests?", "vendor", "db(\\\\|/)([\\w_]*)migrate([_\\w]*)").flatMap {
          directory =>
              List(
                s"(^|\\\\)$directory($$|\\\\)".r.unanchored,
                s"(^|/)$directory($$|/)".r.unanchored
              )
      }

  override def withTypeStubs(value: Boolean): Config =
      copy(useTypeStubs = value).withInheritedFields(this)
end Config

private object Frontend:

  implicit val defaultConfig: Config = Config()

  val cmdLineParser: OParser[Unit, Config] =
    val builder = OParser.builder[Config]
    import builder.*
    OParser.sequence(
      programName("ruby2atom"),
      TypeStubConfig.parserOptions
    )

object Main extends X2CpgMain(cmdLineParser, new Ruby2Atom()):

  def run(config: Config, rubySrc2Cpg: Ruby2Atom): Unit =
      rubySrc2Cpg.run(config)
