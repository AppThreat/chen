package io.appthreat.dataflowengineoss

import io.appthreat.dataflowengineoss.language.dotextension.DdgNodeDot
import io.appthreat.dataflowengineoss.language.nodemethods.{
    ExpressionMethods,
    ExtendedCfgNodeMethods
}
import io.shiftleft.codepropertygraph.generated.nodes.*

package object language:

    implicit def cfgNodeToMethodsQp[NodeType <: CfgNode](node: NodeType)
      : ExtendedCfgNodeMethods[NodeType] =
        new ExtendedCfgNodeMethods(node)

    implicit def expressionMethods[NodeType <: Expression](node: NodeType)
      : ExpressionMethods[NodeType] =
        new ExpressionMethods(node)

    implicit def toExtendedCfgNode[NodeType <: CfgNode](traversal: IterableOnce[NodeType])
      : ExtendedCfgNode =
        new ExtendedCfgNode(traversal.iterator)

    implicit def toDdgNodeDot(traversal: IterableOnce[Method]): DdgNodeDot =
        new DdgNodeDot(traversal.iterator)

    implicit def toDdgNodeDotSingle(method: Method): DdgNodeDot =
        new DdgNodeDot(Iterator.single(method))
end language
