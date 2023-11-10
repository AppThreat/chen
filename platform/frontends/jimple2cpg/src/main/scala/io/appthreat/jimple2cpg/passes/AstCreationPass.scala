package io.appthreat.jimple2cpg.passes

import io.appthreat.jimple2cpg.Config
import io.appthreat.jimple2cpg.util.ProgramHandlingUtil.ClassFile
import io.appthreat.x2cpg.datastructures.Global
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
    private val logger = LoggerFactory.getLogger(classOf[AstCreationPass])

    override def generateParts(): Array[? <: AnyRef] = classFiles.toArray

    override def runOnPart(builder: DiffGraphBuilder, classFile: ClassFile): Unit =
        try
            val sootClass = Scene.v().loadClassAndSupport(classFile.fullyQualifiedClassName.get)
            sootClass.setApplicationClass()
            val localDiff = AstCreator(classFile.file.canonicalPath, sootClass, global)(
              config.schemaValidation
            ).createAst()
            builder.absorb(localDiff)
        catch
            case e: Exception =>
                logger.warn(s"Exception on AST creation for ${classFile.file.canonicalPath}", e)
                Iterator()
end AstCreationPass
