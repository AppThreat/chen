package io.appthreat.ruby2atom.passes

import io.appthreat.ruby2atom.astcreation.AstCreator
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.NodeTypes
import io.shiftleft.codepropertygraph.generated.nodes.NewTypeDecl
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.types.structure.NamespaceTraversal
import overflowdb.BatchedUpdate

class AstCreationPass(cpg: Cpg, astCreators: List[AstCreator])
    extends ForkJoinParallelCpgPass[AstCreator](cpg):

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
end AstCreationPass
