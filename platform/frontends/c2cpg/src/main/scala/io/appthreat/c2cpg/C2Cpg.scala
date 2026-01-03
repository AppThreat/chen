package io.appthreat.c2cpg

import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.passes.{
    AstCreationPass,
    ConfigFileCreationPass,
    PreprocessorPass,
    TypeDeclNodePass
}
import io.appthreat.c2cpg.utils.IncludeAutoDiscovery
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.X2CpgFrontend
import io.appthreat.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages

import java.nio.file.Paths
import scala.util.Try

class C2Cpg extends X2CpgFrontend[Config]:

  def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config) { (cpg, config) =>
        new MetaDataPass(cpg, Languages.NEWC, config.inputPath).createAndApply()
        val updatedConfig = if config.includePathsAutoDiscovery then
          val projectIncludes =
              IncludeAutoDiscovery.discoverProjectIncludePaths(Paths.get(config.inputPath))
          if projectIncludes.nonEmpty then
            println(s"Auto-discovered ${projectIncludes.size} project include paths")
          config.withIncludePaths(config.includePaths ++ projectIncludes.map(_.toString))
        else
          config

        new AstCreationPass(cpg, updatedConfig).createAndApply()

        if !config.onlyAstCache then
          new ConfigFileCreationPass(cpg).createAndApply()
          TypeNodePass.withRegisteredTypes(CGlobal.typesSeen(), cpg).createAndApply()
          new TypeDeclNodePass(cpg)(using config.schemaValidation).createAndApply()
      }

  def printIfDefsOnly(config: Config): Unit =
    val stmts = new PreprocessorPass(config).run().mkString(",")
    println(stmts)
end C2Cpg
