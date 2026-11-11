package io.appthreat.jimple2cpg.passes

import io.appthreat.jimple2cpg.Config
import io.appthreat.jimple2cpg.util.ProgramHandlingUtil.ClassFile
import io.appthreat.x2cpg.datastructures.Global
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import org.slf4j.LoggerFactory
import soot.Scene

/** Creates the AST layer from the given class file and stores all types in the given global
  * parameter.
  * @param classFiles
  *   List of class files and their fully qualified class names
  * @param cpg
  *   The CPG to add to
  */
class AstCreationPass(classFiles: List[ClassFile], cpg: Cpg, config: Config)
    extends ConcurrentWriterCpgPass[ClassFile](cpg):

  val global: Global = new Global()

  private val logger = LoggerFactory.getLogger(getClass)

  override def generateParts(): Array[? <: AnyRef] = classFiles.toArray

  override def runOnPart(builder: DiffGraphBuilder, classFile: ClassFile): Unit =
      try
        val sootClass = Scene.v().loadClassAndSupport(classFile.fullyQualifiedClassName.get)
        sootClass.setApplicationClass()
        val localDiff = AstCreator(classFile.file.canonicalPath, sootClass, global)(
          using config.schemaValidation
        ).createAst()
        builder.absorb(localDiff)
      catch
        case e: Exception =>
            // The whole class is left out of the graph; at debug, like every lost-file message
            logger.debug(
              s"Failed to create the AST for class file '${classFile.file.canonicalPath}', so it is left out",
              e
            )
            ParseReporter.record(
              ParseReporter.Frontend.Jimple,
              classFileLossName(classFile),
              ParseReporter.Outcome.Dropped,
              ParseReporter.Stage.Ast,
              s"${e.getClass.getSimpleName}: ${e.getMessage}"
            )
            Iterator()

  /** The name the report gives a lost class file: its path under the input, or, for a file out of
    * an archive (whose extraction copy lives in a temporary directory), the archive and the entry's
    * package path; a plain directory input names the entry by its package path alone.
    */
  private def classFileLossName(classFile: ClassFile): String =
    val canonical = classFile.file.canonicalPath
    if canonical.startsWith(better.files.File(config.inputPath).canonicalPath) then
      ParseReporter.relativeTo(config.inputPath, canonical)
    else
      val entry =
          classFile.packagePath.map(path => s"$path/").getOrElse("") + classFile.file.name
      classFile.sourceArchivePath match
        case Some(archive) =>
            s"${ParseReporter.relativeTo(config.inputPath, archive)}!$entry"
        case None => entry
end AstCreationPass
