package io.appthreat.jimple2cpg.passes

import io.appthreat.jimple2cpg.Config
import io.appthreat.x2cpg.datastructures.Global
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import soot.{Scene, SootClass, SourceLocator}

/** Creates the AST layer from the given class file and stores all types in the given global
  * parameter.
  */
class SootAstCreationPass(cpg: Cpg, config: Config) extends ConcurrentWriterCpgPass[SootClass](cpg):

  val global: Global = new Global()

  override def generateParts(): Array[? <: AnyRef] = Scene.v().getApplicationClasses.toArray()

  override def runOnPart(builder: DiffGraphBuilder, part: SootClass): Unit =
    val jimpleFile = SourceLocator.v().getSourceForClass(part.getName)
    try
      val localDiff =
          new AstCreator(jimpleFile, part, global)(config.schemaValidation).createAst()
      builder.absorb(localDiff)
    catch
      case e: Exception =>
