package io.appthreat.edg2atom

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.parser.{FileDefaults, ProjectSources}
import io.appthreat.c2cpg.passes.{
    AstCreationPass,
    ConstantTagPass,
    DeclarationAttributesPass,
    ReferenceKindPass,
    TypeDeclNodePass
}
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.passes.{DuplicateDefinitionPass, EdgAstCreationPass, FrontendTagPass}
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.X2CpgFrontend
import io.appthreat.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import org.slf4j.LoggerFactory

import scala.jdk.CollectionConverters.*
import scala.util.Try

/** The C/C++ frontend that builds the graph from the EDG front end's view of each translation unit,
  * exported by edga, in the shapes of the CDT-based frontend (`c2cpg`), whose passes it shares.
  *
  * With `fallbackToCdt`, a translation unit edga cannot export, and the project headers that belong
  * to it, are parsed by the CDT frontend instead; so is the whole project when edga is not
  * installed. Each FILE node says which frontend built it (`frontend=edg|cdt`).
  */
class Edg2Atom(fallbackToCdt: Boolean = false) extends X2CpgFrontend[Config]:

  private val logger = LoggerFactory.getLogger(getClass)

  def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config) { (cpg, config) =>
        CGlobal.reset()
        new MetaDataPass(cpg, Languages.NEWC, config.inputPath).createAndApply()
        val sources  = new ProjectSources(config)
        val runner   = new EdgaRunner(config, sources)
        val relative = (file: String) => SourceFiles.toRelativePath(file, config.inputPath)
        val frontendOf =
            if runner.executable.isEmpty then
              if !fallbackToCdt then
                throw new IllegalStateException(
                  "edga was not found: set EDGA_PATH or the edga.path system property, or put it on the PATH"
                )
              logger.warn("edga was not found: the CDT frontend parses the project")
              parseWithCdt(cpg, config, sources, sources.files.toSeq)
              sources.files.map(f => relative(f) -> FrontendTagPass.Cdt).toMap
            else
              val pass = new EdgAstCreationPass(cpg, config, sources, runner)
              pass.createAndApply()
              val edg = pass.written.asScala.toSeq.map(relative) ++
                  sources.headerOwners.collect {
                      case (header, unit) if pass.written.contains(unit.toString) =>
                          relative(header.toString)
                  }
              val cdt =
                  if fallbackToCdt && !pass.failed.isEmpty then
                    val files = pass.failed.asScala.toSeq.sorted ++ pass.unwrittenHeaders
                    logger.warn(
                      s"edga could not export ${pass.failed.size} units: the CDT frontend parses them"
                    )
                    parseWithCdt(cpg, config, sources, files)
                    files.map(relative)
                  else Nil
              edg.map(_ -> FrontendTagPass.Edg).toMap ++ cdt.map(_ -> FrontendTagPass.Cdt)
        new DuplicateDefinitionPass(cpg).createAndApply()
        new FrontendTagPass(cpg, frontendOf).createAndApply()
        TypeNodePass.withRegisteredTypes(CGlobal.typesSeen(), cpg).createAndApply()
        new TypeDeclNodePass(cpg, CGlobal.lastMembers)(using config.schemaValidation).createAndApply()
        new ConstantTagPass(cpg, CGlobal.lastConstants).createAndApply()
        new ReferenceKindPass(cpg, CGlobal.lastArrayTypedefs).createAndApply()
        new DeclarationAttributesPass(cpg).createAndApply()
      }

  /** The CDT frontend's ASTs for `files`. */
  private def parseWithCdt(
    cpg: Cpg,
    config: Config,
    sources: ProjectSources,
    files: Seq[String]
  ): Unit =
      new AstCreationPass(cpg, config, projectSources = sources):
        override def generateParts(): Array[String] = files.toArray
      .createAndApply()
end Edg2Atom
