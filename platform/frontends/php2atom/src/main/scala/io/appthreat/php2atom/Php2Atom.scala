package io.appthreat.php2atom

import io.appthreat.php2atom.parser.PhpParser
import io.appthreat.php2atom.passes.*
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.X2CpgFrontend
import io.appthreat.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass}
import io.appthreat.x2cpg.utils.ExternalCommand
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.passes.CpgPassBase
import org.slf4j.LoggerFactory

import scala.collection.mutable
import scala.util.{Failure, Success, Try}

class Php2Atom extends X2CpgFrontend[Config]:
  private val logger = LoggerFactory.getLogger(this.getClass)

  private def isPhpVersionSupported: Boolean =
    val result = ExternalCommand.run("php --version", ".")
    result match
      case Success(listString) =>
          true
      case Failure(exception) =>
          logger.debug(s"Failed to run php --version: ${exception.getMessage}")
          false

  override def createCpg(config: Config): Try[Cpg] =
    val errorMessages = mutable.ListBuffer[String]()

    val parser = PhpParser.getParser(config)

    if parser.isEmpty then
      errorMessages.append("Could not initialize PhpParser")
    if !isPhpVersionSupported then
      errorMessages.append(
        "PHP version not supported. Is PHP 7.1.0 or above installed and available on your path?"
      )

    if errorMessages.isEmpty then
      withNewEmptyCpg(config.outputPath, config: Config) { (cpg, config) =>
        new MetaDataPass(cpg, Languages.PHP, config.inputPath).createAndApply()
        new AstCreationPass(config, cpg, parser.get)(
          config.schemaValidation
        ).createAndApply()
        new ConfigFileCreationPass(cpg).createAndApply()
        new AstParentInfoPass(cpg).createAndApply()
        new AnyTypePass(cpg).createAndApply()
        TypeNodePass.withTypesFromCpg(cpg).createAndApply()
        LocalCreationPass.allLocalCreationPasses(cpg).foreach(_.createAndApply())
        new ClosureRefPass(cpg).createAndApply()
      }
    else
      val errorOutput = (
        "Skipping AST creation as php/php-parser could not be executed." ::
            errorMessages.toList
      ).mkString("\n- ")

      logger.debug(errorOutput)

      Failure(new RuntimeException("php not found or version not supported"))
    end if
  end createCpg
end Php2Atom

object Php2Atom:

  def postProcessingPasses(cpg: Cpg, config: Option[Config] = None): List[CpgPassBase] =
      List(new PhpSetKnownTypesPass(cpg))
