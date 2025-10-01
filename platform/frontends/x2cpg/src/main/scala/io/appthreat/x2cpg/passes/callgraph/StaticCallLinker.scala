package io.appthreat.x2cpg.passes.callgraph

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes}
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*
import scala.collection.mutable

class StaticCallLinker(cpg: Cpg) extends ForkJoinParallelCpgPass[Seq[Call]](cpg, maxChunkSize = 25):

  override def generateParts(): Array[Seq[Call]] =
      cpg.call.where(_.dispatchTypeNot(DispatchTypes.DYNAMIC_DISPATCH)).grouped(10).toArray

  override def runOnPart(builder: DiffGraphBuilder, calls: Seq[Call]): Unit =
      calls.foreach { call =>
          try
            linkCall(call, builder)
          catch
            case exception: Exception =>
                throw new RuntimeException(exception)
      }
  def linkCall(
    call: Call,
    builder: DiffGraphBuilder
  ): Unit =
      call.dispatchType match
        case DispatchTypes.STATIC_DISPATCH | DispatchTypes.INLINED =>
            val resolvedMethods = cpg.method.fullNameExact(call.methodFullName).l
            resolvedMethods.foreach(dst => builder.addEdge(call, dst, EdgeTypes.CALL))
        case DispatchTypes.DYNAMIC_DISPATCH =>
        case _                              =>

end StaticCallLinker
