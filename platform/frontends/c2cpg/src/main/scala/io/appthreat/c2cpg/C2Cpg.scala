package io.appthreat.c2cpg

import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.passes.{
    AstCreationPass,
    ConfigFileCreationPass,
    PreprocessorPass,
    TypeDeclNodePass
}
import io.appthreat.c2cpg.utils.Report
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.X2CpgFrontend
import io.appthreat.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages

import scala.util.Try

class C2Cpg extends X2CpgFrontend[Config]:

    private val report: Report = new Report()

    def createCpg(config: Config): Try[Cpg] =
        withNewEmptyCpg(config.outputPath, config) { (cpg, config) =>
            new MetaDataPass(cpg, Languages.NEWC, config.inputPath).createAndApply()
            new AstCreationPass(cpg, config, report).createAndApply()
            new ConfigFileCreationPass(cpg).createAndApply()
            TypeNodePass.withRegisteredTypes(CGlobal.typesSeen(), cpg).createAndApply()
            new TypeDeclNodePass(cpg)(config.schemaValidation).createAndApply()
            report.print()
        }

    def printIfDefsOnly(config: Config): Unit =
        val stmts = new PreprocessorPass(config).run().mkString(",")
        println(stmts)
