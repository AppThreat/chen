package io.appthreat.dataflowengineoss.dotgenerator

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.dotgenerator.{AstGenerator, CdgGenerator, CfgGenerator, DotSerializer}

object DotCpg14Generator {

  def toDotCpg14(traversal: Iterator[Method])(implicit semantics: Semantics = DefaultSemantics()): Iterator[String] =
    traversal.map(dotGraphForMethod)

  private def dotGraphForMethod(method: Method)(implicit semantics: Semantics): String = {
    val ast = new AstGenerator().generate(method)
    val cfg = new CfgGenerator().generate(method)
    val ddg = new DdgGenerator().generate(method)
    val cdg = new CdgGenerator().generate(method)
    DotSerializer.dotGraph(Option(method), ast ++ cfg ++ ddg ++ cdg, withEdgeTypes = true)
  }

}
