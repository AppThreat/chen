package io.appthreat.x2cpg.passes.callgraph

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.*
import io.shiftleft.passes.CpgPass
import io.appthreat.x2cpg.passes.linking.InternalLinkage
import io.appthreat.x2cpg.utils.LinkingUtil
import io.shiftleft.semanticcpg.language.*

/** This pass has MethodStubCreator and TypeDeclStubCreator as prerequisite for language frontends
  * which do not provide method stubs and type decl stubs.
  */
class MethodRefLinker(cpg: Cpg) extends CpgPass(cpg) with LinkingUtil:

  override def run(dstGraph: DiffGraphBuilder): Unit =
    // a `static` function referenced by name resolves in the referencing file's own translation unit
    val linkage = InternalLinkage(cpg)
    // Create REF edges from METHOD_REFs to METHOD
    linkToSingle(
      cpg,
      srcLabels = List(NodeTypes.METHOD_REF),
      dstNodeLabel = NodeTypes.METHOD,
      edgeType = EdgeTypes.REF,
      dstNodeMap = methodFullNameToNode(cpg, _),
      dstFullNameKey = PropertyNames.METHOD_FULL_NAME,
      dstGraph,
      None,
      dstNodeFor = Some { (src, fullName) =>
        val candidates = cpg.method.fullNameExact(fullName).l
        if candidates.exists(linkage.hasInternalLinkage) then
          linkage.visibleFrom(src, candidates).headOption
        else methodFullNameToNode(cpg, fullName)
      }
    )
  end run
end MethodRefLinker
