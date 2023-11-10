package io.appthreat.dataflowengineoss.dotgenerator

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.dotgenerator.DotSerializer

object DotDdgGenerator:

    def toDotDdg(traversal: Iterator[Method])(implicit
      semantics: Semantics = DefaultSemantics()
    ): Iterator[String] =
        traversal.map(dotGraphForMethod)

    private def dotGraphForMethod(method: Method)(implicit semantics: Semantics): String =
        val ddgGenerator = new DdgGenerator()
        val ddg          = ddgGenerator.generate(method)
        DotSerializer.dotGraph(Option(method), ddg)
