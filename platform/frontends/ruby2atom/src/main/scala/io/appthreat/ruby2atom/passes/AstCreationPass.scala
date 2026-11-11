package io.appthreat.ruby2atom.passes

import io.appthreat.ruby2atom.astcreation.AstCreator
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.NodeTypes
import io.shiftleft.codepropertygraph.generated.nodes.NewTypeDecl
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.types.structure.NamespaceTraversal
import org.slf4j.LoggerFactory
import overflowdb.BatchedUpdate

/** `inputPath` is only for the parse-failure report, to name a lost file relative to the project
  * root rather than by its absolute path.
  */
class AstCreationPass(cpg: Cpg, astCreators: List[AstCreator], inputPath: String = "")
    extends ForkJoinParallelCpgPass[AstCreator](cpg):

  private val logger = LoggerFactory.getLogger(getClass)

  override def generateParts(): Array[AstCreator] = astCreators.toArray

  override def init(): Unit =
    // The first entry will be the <empty> type, which is often found on fieldAccess nodes
    //   (which may be receivers to calls)
    val diffGraph = new DiffGraphBuilder
    val emptyType =
        NewTypeDecl()
            .astParentType(NodeTypes.NAMESPACE_BLOCK)
            .astParentFullName(NamespaceTraversal.globalNamespaceName)
            .isExternal(true)
    val anyType =
        NewTypeDecl()
            .name(Defines.Any)
            .fullName(Defines.Any)
            .astParentType(NodeTypes.NAMESPACE_BLOCK)
            .astParentFullName(NamespaceTraversal.globalNamespaceName)
            .isExternal(true)
    diffGraph.addNode(emptyType).addNode(anyType)
    BatchedUpdate.applyDiff(cpg.graph, diffGraph)

  override def runOnPart(diffGraph: DiffGraphBuilder, astCreator: AstCreator): Unit =
      try
        val ast = astCreator.createAst()
        diffGraph.absorb(ast)
      catch
        case ex: Exception =>
            // The whole file is left out of the graph; at debug, like every lost-file message
            logger.debug(s"Failed to create AST for file '${astCreator.fileName}'", ex)
            val name =
                if inputPath.nonEmpty then
                  ParseReporter.relativeTo(inputPath, astCreator.fileName)
                else astCreator.fileName
            ParseReporter.record(
              ParseReporter.Frontend.Ruby,
              name,
              ParseReporter.Outcome.Dropped,
              ParseReporter.Stage.Ast,
              ParseReporter.describe(ex)
            )
end AstCreationPass
