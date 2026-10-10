package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.Imports.createImportNodeAndLink
import io.appthreat.x2cpg.passes.frontend.XImportsPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.operatorextension.OpNodes.Assignment

class ImportsPass(cpg: Cpg) extends XImportsPass(cpg):

  override protected val importCallName: String = "import"

  override protected def importCallToPart(x: Call): Iterator[(Call, Assignment)] =
      x.inAssignment.map(y => (x, y))

  /** As the generic pass, plus: an import the frontend tagged `lazy-import` (PEP 810) passes that
    * tag on to its IMPORT node, so import-level consumers see the laziness without walking back to
    * the call. The call's own TAG node is reused, not duplicated.
    */
  override def runOnPart(diffGraph: DiffGraphBuilder, part: (Call, Assignment)): Unit =
    val (call, assignment) = part
    val importNode =
        createImportNodeAndLink(
          importedEntityFromCall(call),
          assignment.target.code,
          Some(call),
          diffGraph
        )
    call.tag.nameExact(PythonLazyImports.Tag).foreach { tag =>
        diffGraph.addEdge(importNode, tag, EdgeTypes.TAGGED_BY)
    }

  override def importedEntityFromCall(call: Call): String =
      call.argument.code.l match
        case List("", what)       => what
        case List(where, what)    => s"$where.$what"
        case List("", what, _)    => what
        case List(where, what, _) => s"$where.$what"
        case _                    => ""
end ImportsPass
