package io.shiftleft.semanticcpg.language.nodemethods

import io.shiftleft.Implicits.IterableOnceDeco
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.NodeExtension
import io.shiftleft.semanticcpg.language.*

import scala.annotation.tailrec
import scala.jdk.CollectionConverters.*

class CfgNodeMethods(val node: CfgNode) extends AnyVal with NodeExtension:

  /** Successors in the CFG
    */
  def cfgNext: Iterator[CfgNode] =
      Iterator.single(node).cfgNext

  /** Maps each node in the traversal to a traversal returning its n successors.
    */
  def cfgNext(n: Int): Iterator[CfgNode] = n match
    case 0 => Iterator.empty
    case _ => cfgNext.flatMap(x => List(x) ++ x.cfgNext(n - 1))

  /** Maps each node in the traversal to a traversal returning its n predecessors.
    */
  def cfgPrev(n: Int): Iterator[CfgNode] = n match
    case 0 => Iterator.empty
    case _ => cfgPrev.flatMap(x => List(x) ++ x.cfgPrev(n - 1))

  /** Predecessors in the CFG
    */
  def cfgPrev: Iterator[CfgNode] =
      Iterator.single(node).cfgPrev

  /** Recursively determine all nodes on which this CFG node is control-dependent.
    */
  def controlledBy: Iterator[CfgNode] =
      expandExhaustively { v =>
          v._cdgIn
      }

  /** Recursively determine all nodes which this CFG node controls
    */
  def controls: Iterator[CfgNode] =
      expandExhaustively { v =>
          v._cdgOut
      }

  /** Recursively determine all nodes by which this node is dominated
    */
  def dominatedBy: Iterator[CfgNode] =
      expandExhaustively { v =>
          v._dominateIn
      }

  /** Recursively determine all nodes which are dominated by this node
    */
  def dominates: Iterator[CfgNode] =
      expandExhaustively { v =>
          v._dominateOut
      }

  /** Recursively determine all nodes by which this node is post dominated
    */
  def postDominatedBy: Iterator[CfgNode] =
      expandExhaustively { v =>
          v._postDominateIn
      }

  /** Recursively determine all nodes which are post dominated by this node
    */
  def postDominates: Iterator[CfgNode] =
      expandExhaustively { v =>
          v._postDominateOut
      }

  private def expandExhaustively(expand: CfgNode => Iterator[StoredNode]): Iterator[CfgNode] =
    var controllingNodes = List.empty[CfgNode]
    var visited          = Set.empty + node
    var worklist         = node :: Nil

    while worklist.nonEmpty do
      val vertex = worklist.head
      worklist = worklist.tail

      expand(vertex).foreach { case controllingNode: CfgNode =>
          if !visited.contains(controllingNode) then
            visited += controllingNode
            controllingNodes = controllingNode :: controllingNodes
            worklist = controllingNode :: worklist
      }
    controllingNodes.iterator

  def method: Method = node match
    case node: Method => node
    case _: MethodParameterIn | _: MethodParameterOut | _: MethodReturn =>
        walkUpAst(node)
    case _: CallRepr if !node.isInstanceOf[Call]    => walkUpAst(node)
    case _: Annotation | _: AnnotationLiteral       => node.inAst.collectAll[Method].head
    case _: Expression | _: JumpTarget | _: Literal => walkUpContains(node)
    case _ => throw new MatchError(s"Unexpected node type: ${node.getClass}")

  /** Obtain hexadecimal string representation of lineNumber field.
    *
    * Binary frontends store addresses in the lineNumber field as integers. For interoperability
    * with other binary analysis tooling, it is convenient to allow retrieving these as hex strings.
    */
  def address: Option[String] =
      node.lineNumber.map(_.toLong.toHexString)

  @tailrec
  private def walkUpAst(node: CfgNode): Method =
    val parent = node._astIn.nextOption().orNull
    parent match
      case m: Method  => m
      case c: CfgNode => walkUpAst(c)
      case _          => null

  @tailrec
  private def walkUpContains(node: StoredNode): Method =
    val parent = node._containsIn.nextOption().orNull
    parent match
      case method: Method => method
      case typeDecl: TypeDecl =>
          typeDecl.astParent match
            case namespaceBlock: NamespaceBlock =>
                // For Typescript, types may be declared in namespaces which we represent as NamespaceBlocks
                namespaceBlock.inAst.collectAll[Method].headOption.orNull
            case method: Method =>
                // For a language such as Javascript, types may be dynamically declared under procedures
                method
            case _ =>
                // there are csharp CPGs that have typedecls here, which is invalid.
                null
      case other: StoredNode =>
          walkUpContains(other)
      case null =>
          node match
            case node: CfgNode => walkUpAst(node)
            case _             => null
  end walkUpContains
end CfgNodeMethods
