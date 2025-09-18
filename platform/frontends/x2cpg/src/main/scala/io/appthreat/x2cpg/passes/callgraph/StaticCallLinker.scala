package io.appthreat.x2cpg.passes.callgraph

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import scala.collection.mutable

class StaticCallLinker(cpg: Cpg, maxEdgesPerCall: Int = 100000) extends CpgPass(cpg):

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val methodFullNameToNode = mutable.Map.empty[String, List[Method]]

    cpg.method.foreach { method =>
        methodFullNameToNode.updateWith(method.fullName) {
            case Some(l) => Some(method :: l)
            case None    => Some(List(method))
        }
    }

    cpg.call.foreach { call =>
        try
          linkCall(call, dstGraph, methodFullNameToNode)
        catch
          case exception: Exception =>
              throw new RuntimeException(exception)
    }

  private def linkCall(
    call: Call,
    dstGraph: DiffGraphBuilder,
    methodMap: mutable.Map[String, List[Method]]
  ): Unit =
      call.dispatchType match
        case DispatchTypes.STATIC_DISPATCH | DispatchTypes.INLINED =>
            linkStaticCall(call, dstGraph, methodMap)
        case DispatchTypes.DYNAMIC_DISPATCH =>
        // Do nothing
        case _ =>

  private def linkStaticCall(
    call: Call,
    dstGraph: DiffGraphBuilder,
    methodMap: mutable.Map[String, List[Method]]
  ): Unit =
    val resolvedMethodOption = methodMap.get(call.methodFullName)
    if resolvedMethodOption.isDefined then
      val methods = resolvedMethodOption.get
      val methodsToLink = if methods.length > maxEdgesPerCall then
        methods.take(maxEdgesPerCall)
      else
        methods

      methodsToLink.foreach { method =>
          dstGraph.addEdge(call, method, EdgeTypes.CALL)
      }

end StaticCallLinker
