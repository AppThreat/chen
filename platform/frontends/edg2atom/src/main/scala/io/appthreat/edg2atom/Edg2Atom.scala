package io.appthreat.edg2atom

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.parser.ProjectSources
import io.appthreat.c2cpg.passes.{
    ConstantTagPass,
    DeclarationAttributesPass,
    ReferenceKindPass,
    TypeDeclNodePass
}
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.passes.EdgAstCreationPass
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.X2CpgFrontend
import io.appthreat.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages

import scala.util.Try

/** The C/C++ frontend that builds the graph from the EDG front end's view of each translation unit,
  * exported by edga, in the shapes of the CDT-based frontend (`c2cpg`), whose passes it shares.
  */
class Edg2Atom extends X2CpgFrontend[Config]:

  def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config) { (cpg, config) =>
        CGlobal.reset()
        new MetaDataPass(cpg, Languages.NEWC, config.inputPath).createAndApply()
        val sources = new ProjectSources(config)
        val runner  = new EdgaRunner(config, sources)
        if runner.executable.isEmpty then
          throw new IllegalStateException(
            "edga was not found: set EDGA_PATH or the edga.path system property, or put it on the PATH"
          )
        new EdgAstCreationPass(cpg, config, sources, runner).createAndApply()
        TypeNodePass.withRegisteredTypes(CGlobal.typesSeen(), cpg).createAndApply()
        new TypeDeclNodePass(cpg, CGlobal.lastMembers)(using config.schemaValidation).createAndApply()
        new ConstantTagPass(cpg, CGlobal.lastConstants).createAndApply()
        new ReferenceKindPass(cpg, CGlobal.lastArrayTypedefs).createAndApply()
        new DeclarationAttributesPass(cpg).createAndApply()
      }
end Edg2Atom
