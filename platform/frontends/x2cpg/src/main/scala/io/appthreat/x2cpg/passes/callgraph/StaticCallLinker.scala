package io.appthreat.x2cpg.passes.callgraph

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

class StaticCallLinker(cpg: Cpg) extends CpgPass(cpg):

  private val methodFullNameToNode = mutable.Map.empty[String, List[Method]]

  override def run(dstGraph: DiffGraphBuilder): Unit =

    cpg.method.foreach { method =>
        methodFullNameToNode.updateWith(method.fullName) {
            case Some(l) => Some(method :: l)
            case None    => Some(List(method))
        }
    }

    cpg.call.foreach { call =>
        try
          linkCall(call, dstGraph)
        catch
          case exception: Exception =>
              throw new RuntimeException(exception)
    }

  private def linkCall(call: Call, dstGraph: DiffGraphBuilder): Unit =
      call.dispatchType match
        case DispatchTypes.STATIC_DISPATCH | DispatchTypes.INLINED =>
            linkStaticCall(call, dstGraph)
        case DispatchTypes.DYNAMIC_DISPATCH =>
        // Do nothing
        case _ =>

  private def linkStaticCall(call: Call, dstGraph: DiffGraphBuilder): Unit =
    val resolvedMethodOption = methodFullNameToNode.get(call.methodFullName)
    if resolvedMethodOption.isDefined then
      resolvedMethodOption.get.foreach { dst =>
          dstGraph.addEdge(call, dst, EdgeTypes.CALL)
      }

end StaticCallLinker
