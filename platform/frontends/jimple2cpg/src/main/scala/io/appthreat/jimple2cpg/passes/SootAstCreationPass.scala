package io.appthreat.jimple2cpg.passes

import io.appthreat.jimple2cpg.Config
import io.appthreat.x2cpg.datastructures.Global
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import org.slf4j.LoggerFactory
import soot.{Scene, SootClass, SourceLocator}

/** Creates the AST layer from the given class file and stores all types in the given global
  * parameter.
  */
class SootAstCreationPass(cpg: Cpg, config: Config) extends ConcurrentWriterCpgPass[SootClass](cpg):

  val global: Global = new Global()

  private val logger = LoggerFactory.getLogger(getClass)

  override def generateParts(): Array[? <: AnyRef] = Scene.v().getApplicationClasses.toArray()

  override def runOnPart(builder: DiffGraphBuilder, part: SootClass): Unit =
    val jimpleFile = SourceLocator.v().getSourceForClass(part.getName)
    try
      val localDiff =
          new AstCreator(jimpleFile, part, global)(using config.schemaValidation).createAst()
      builder.absorb(localDiff)
    catch
      case e: Exception =>
          // The whole class is left out of the graph; at debug, like every lost-file message
          val className = Option(jimpleFile).filter(_.nonEmpty).getOrElse(s"${part.getName}.class")
          logger.debug(s"Failed to create the AST for class '$className', so it is left out", e)
          ParseReporter.record(
            ParseReporter.Frontend.Jimple,
            className,
            ParseReporter.Outcome.Dropped,
            ParseReporter.Stage.Ast,
            ParseReporter.describe(e)
          )
end SootAstCreationPass
