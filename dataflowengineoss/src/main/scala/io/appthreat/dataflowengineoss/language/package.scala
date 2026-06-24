package io.appthreat.dataflowengineoss

import io.appthreat.dataflowengineoss.language.dotextension.DdgNodeDot
import io.appthreat.dataflowengineoss.language.nodemethods.{
    ExpressionMethods,
    ExtendedCfgNodeMethods
}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import scala.language.implicitConversions

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

  implicit def toExtendedPathsTrav[NodeType <: Path](traversal: IterableOnce[NodeType]): PassesExt =
      new PassesExt(traversal.iterator)

  class PassesExt(traversal: Iterator[Path]):

    def passes(trav: Iterator[AstNode] => Iterator[?]): Iterator[Path] =
        traversal.filter(_.elements.exists(_.start.where(trav).nonEmpty))

    def passesNot(trav: Iterator[AstNode] => Iterator[?]): Iterator[Path] =
        traversal.filter(_.elements.forall(_.start.where(trav).isEmpty))

    /** Keep only flows that pass through at least one node matching `predicate`. A node-level
      * predicate is far easier to express than the traversal-function form of [[passes]], e.g.
      * `flows.passesThrough(_.isCall)` or `flows.passesThrough(_.tag.name("sink").nonEmpty)`.
      */
    def passesThrough(predicate: AstNode => Boolean): Iterator[Path] =
        traversal.filter(_.elements.exists(predicate))

    /** Drop flows that pass through any node matching `predicate`, keeping the rest. This is the
      * natural way to remove flows neutralised by a sanitiser or validator, e.g.
      * `flows.doesNotPassThrough(n => sanitizerIds.contains(n.id))`.
      */
    def doesNotPassThrough(predicate: AstNode => Boolean): Iterator[Path] =
        traversal.filterNot(_.elements.exists(predicate))
  end PassesExt

end language
