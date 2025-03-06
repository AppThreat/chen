package io.appthreat.jimple2cpg.passes

import io.appthreat.jimple2cpg.Config
import io.appthreat.jimple2cpg.util.ProgramHandlingUtil.ClassFile
import io.appthreat.x2cpg.datastructures.Global
import io.appthreat.x2cpg.utils.FileUtil.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import better.files.{DefaultCharset, File}
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

  override def generateParts(): Array[? <: AnyRef] = classFiles.toArray

  override def runOnPart(builder: DiffGraphBuilder, classFile: ClassFile): Unit =
      try
        val sootClass = Scene.v().loadClassAndSupport(classFile.fullyQualifiedClassName.get)
        sootClass.setApplicationClass()
        val localDiff = AstCreator(classFile.file.absolutePathAsString, sootClass, global)(
          config.schemaValidation
        ).createAst()
        builder.absorb(localDiff)
      catch
        case e: Exception =>
            Iterator()
