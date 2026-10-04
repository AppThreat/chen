package io.appthreat.edg2atom.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{NewFile, NewTag}
import io.shiftleft.passes.CpgPass

/** Which frontend built each file's AST: a `frontend` tag (`edg` or `cdt`) on its FILE node. */
class FrontendTagPass(cpg: Cpg, frontendOf: Map[String, String]) extends CpgPass(cpg):

  override def run(diffGraph: DiffGraphBuilder): Unit =
    val tags = frontendOf.values.toSeq.distinct.map { frontend =>
        frontend -> NewTag().name(FrontendTagPass.Tag).value(frontend)
    }.toMap
    frontendOf.toSeq.sorted.foreach { (name, frontend) =>
      val file = NewFile().name(name).order(0)
      diffGraph.addNode(file)
      diffGraph.addEdge(file, tags(frontend), EdgeTypes.TAGGED_BY)
    }

object FrontendTagPass:
  val Tag = "frontend"
  val Edg = "edg"
  val Cdt = "cdt"
