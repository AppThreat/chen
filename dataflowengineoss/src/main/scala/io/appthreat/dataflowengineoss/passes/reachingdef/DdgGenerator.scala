package io.appthreat.dataflowengineoss.passes.reachingdef

import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.appthreat.dataflowengineoss.{GlobalScopeMethodNames, globalFromLiteral}
import io.appthreat.dataflowengineoss.queryengine.AccessPathUsage.toTrackedBaseAndAccessPathSimple
import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes, Operators, PropertyNames}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.accesspath.MatchResult
import io.shiftleft.semanticcpg.language.operatorextension.allAssignmentTypes
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.{Set, mutable}

/** Creation of data dependence edges based on solution of the ReachingDefProblem.
  */
class DdgGenerator(
  semantics: Semantics,
  sharedCache: DdgSharedCache = new DdgSharedCache(sharedAcrossMethods = false)
):

  implicit val s: Semantics = semantics

  /** Once reaching definitions have been computed, we create a data dependence graph by checking
    * which reaching definitions are relevant, meaning that a symbol is propagated that is used by
    * the target node.
    *
    * @param dstGraph
    *   the diff graph to add edges to
    * @param problem
    *   the reaching definition problem
    * @param solution
    *   the solution to `problem`
    */
  def addReachingDefEdges(
    dstGraph: DiffGraphBuilder,
    method: Method,
    problem: DataFlowProblem[StoredNode, mutable.BitSet],
    solution: Solution[StoredNode, mutable.BitSet]
  ): Unit =
    implicit val implicitDst: DiffGraphBuilder = dstGraph

    val numberToNode = problem.flowGraph.asInstanceOf[ReachingDefFlowGraph].numberToNode
    val in           = solution.in
    val gen = solution.problem.transferFunction.asInstanceOf[ReachingDefTransferFunction].gen

    val allNodes = in.keys.toList
    // JavaScript-only refinements of the def-use edges: nested member reads and closure captures.
    val nestedContainers = sharedCache.isJavaScript(method)
    val usageAnalyzer    = new UsageAnalyzer(problem, in, nestedContainers)

    /** Add an edge from the entry node to each node that does not have other incoming definitions.
      */
    def addEdgesFromEntryNode(): Unit =
        // Add edges from the entry node
        allNodes
            .filter(n => isDdgNode(n) && usageAnalyzer.usedIncomingDefs(n).isEmpty)
            .foreach { node =>
                addEdge(method, node)
            }

    // This handles `foo(new Bar()) or return new Bar()`
    def addEdgeForBlock(block: Block, towards: StoredNode): Unit =
        block.astChildren.lastOption match
          case None => // Do nothing
          case Some(node: Identifier) =>
              val edgesToAdd = in(node).toList
                  .flatMap(numberToNode.get)
                  .filter(inDef => usageAnalyzer.isUsing(node, inDef))
                  .collect {
                      case identifier: Identifier => identifier
                      case call: Call             => call
                  }
              edgesToAdd.foreach { inNode =>
                  addEdge(inNode, block, nodeToEdgeLabel(inNode))
              }
              if edgesToAdd.nonEmpty then
                addEdge(block, towards)
          case Some(node: Call) =>
              addEdge(node, block, nodeToEdgeLabel(node))
              addEdge(block, towards)
          case _ => // Do nothing
    /** Adds incoming edges to arguments of call sites, including edges between arguments of the
      * same call site.
      */
    def addEdgesToCallSite(call: Call): Unit =
      // Edges between arguments of call sites
      usageAnalyzer.usedIncomingDefs(call).foreach { case (use, ins) =>
          ins.foreach { in =>
            val inNode = numberToNode(in)
            if inNode != use then
              addEdge(inNode, use, nodeToEdgeLabel(inNode))
          }
      }

      // For all calls, assume that input arguments
      // taint corresponding output arguments
      // and the return value. We filter invalid
      // edges at query time (according to the given semantic).
      usageAnalyzer.uses(call).foreach { use =>
          gen(call).foreach { g =>
            val genNode = numberToNode(g)
            if use != genNode && isDdgNode(use) then
              addEdge(use, genNode, nodeToEdgeLabel(use))
          }
      }

      // JavaScript: a read of a read (`route.query.next`, `e.data[k]`, `path.split('#')[1]`) takes
      // its value from the inner expression. Field and index accesses generate no definition of
      // their own, so that taint passes through them unharmed, and that also left the inner
      // expression with no edge into the access on its result: a value tagged at `route.query`
      // never reached `route.query.next`, and a walk that starts AT the access (`data.motd`, the
      // `{@html data.motd}` sink) found no incoming edge at all when the base was a plain
      // identifier.
      if nestedContainers && usageAnalyzer.isContainerAccess(call) then
        call.argument.headOption.foreach {
            case inner: Call => addEdge(inner, call, nodeToEdgeLabel(inner))
            case _           =>
        }

      // This handles `foo(new Bar())`, which is lowered to
      // `foo({Bar tmp = Bar.alloc(); tmp.init(); tmp})`. A macro invocation's value is its
      // expansion's, the block it holds: `CMD` for `#define CMD data` is `data`.
      val blocks = call.argument.isBlock.l ++
          (if call.dispatchType == DispatchTypes.INLINED then call.astChildren.isBlock.l else Nil)
      blocks.distinct.foreach { block => addEdgeForBlock(block, call) }
    end addEdgesToCallSite

    def addEdgesToReturn(ret: Return): Unit =
      // This handles `return new Bar()`, which is lowered to
      // `return {Bar tmp = Bar.alloc(); tmp.init(); tmp}`
      usageAnalyzer.uses(ret).collectAll[Block].foreach(block => addEdgeForBlock(block, ret))
      usageAnalyzer.usedIncomingDefs(ret).foreach {
          case (use: CfgNode, inElements) =>
              addEdge(use, ret, use.code)
              inElements
                  .filterNot(x => numberToNode.get(x).contains(use))
                  .flatMap(numberToNode.get)
                  .foreach { inElemNode =>
                      addEdge(inElemNode, use, nodeToEdgeLabel(inElemNode))
                  }
              if inElements.isEmpty then
                addEdge(method, ret)
          case (_, _) =>
      }
      addEdge(ret, method.methodReturn, "<RET>")

    def addEdgesToMethodParameterOut(paramOut: MethodParameterOut): Unit =
      // There is always an edge from the method input parameter
      // to the corresponding method output parameter as modifications
      // of the input parameter only affect a copy.
      paramOut.paramIn.foreach { paramIn =>
          addEdge(paramIn, paramOut, paramIn.name)
      }
      usageAnalyzer.usedIncomingDefs(paramOut).foreach { case (_, inElements) =>
          inElements.foreach { inElement =>
            val inElemNode = numberToNode(inElement)
            val edgeLabel  = nodeToEdgeLabel(inElemNode)
            addEdge(inElemNode, paramOut, edgeLabel)
          }
      }

    def addEdgesToExitNode(exitNode: MethodReturn): Unit =
        in(exitNode).foreach { i =>
          val iNode = numberToNode(i)
          addEdge(iNode, exitNode, nodeToEdgeLabel(iNode))
        }

    /** This is part of the Lone-identifier optimization: as we remove lone identifiers from `gen`
      * sets, we must now retrieve them and create an edge from each lone identifier to the exit
      * node.
      */
    def addEdgesFromLoneIdentifiersToExit(method: Method): Unit =
      val numberToNode = problem.flowGraph.asInstanceOf[ReachingDefFlowGraph].numberToNode
      val exitNode     = method.methodReturn
      val transferFunction =
          solution.problem.transferFunction.asInstanceOf[OptimizedReachingDefTransferFunction]
      val genOnce = transferFunction.loneIdentifiers
      genOnce.foreach { case (_, defs) =>
          defs.foreach { d =>
            val dNode = numberToNode(d)
            addEdge(dNode, exitNode, nodeToEdgeLabel(dNode))
          }
      }

    def addEdgesToCapturedIdentifiersAndParameters(): Unit =
      def firstUsages(identifier: Identifier): List[Identifier] =
          sharedCache.firstUsages(identifier)
      def firstAndLastUsages(identifier: Identifier): List[(Identifier, Identifier)] =
          sharedCache.firstAndLastUsages(identifier)

      val identifierDestPairs =
          method._identifierViaContainsOut.flatMap { identifier =>
              firstAndLastUsages(identifier)
                  .flatMap { case (firstUsage, lastUsage) =>
                      (
                        identifier.lineNumber,
                        firstUsage.lineNumber,
                        lastUsage.lineNumber
                      ) match
                        case (Some(iNo), Some(fNo), _) if iNo <= fNo =>
                            Some(identifier, firstUsage)
                        case (Some(iNo), _, Some(lNo)) if iNo >= lNo =>
                            Some(lastUsage, identifier)
                        case _ => None
                  }
          }.distinct

      identifierDestPairs
          .foreach { case (src, dst) =>
              addEdge(src, dst, nodeToEdgeLabel(src))
          }
      // JavaScript: every read of a captured variable inside the closure sees the outer value, not
      // only the first one. Components define their handlers and effects as closures over what
      // they read at the top (`const next = params.get('next'); useEffect(() => { if (next)
      // location.href = next })`), and a use in the closure defines nothing for a later use to be
      // reached from, so an edge to the first read alone (the `if (next)` test) left the read in
      // the sink unconnected.
      if nestedContainers then
        method._identifierViaContainsOut.foreach { identifier =>
            firstUsages(identifier).foreach { usage =>
                if usage.method != method &&
                  identifier.lineNumber.zip(usage.lineNumber).exists((i, u) =>
                      i.intValue <= u.intValue
                  )
                then addEdge(identifier, usage, nodeToEdgeLabel(identifier))
            }
        }
      method.parameter.foreach { param =>
          param.capturedByMethodRef.referencedMethod.ast.isIdentifier.foreach { identifier =>
              addEdge(param, identifier, nodeToEdgeLabel(param))
          }
      }

      // `globalFromLiteral(lit)` is non-empty only when an assignment among the literal's AST
      // ancestors (up to the nearest METHOD) belongs to a global-scope method. The literals that can
      // qualify are therefore those in the AST of such an assignment, without crossing into a
      // nested METHOD - found by walking down from the few qualifying assignments, instead of
      // walking up from every literal of the file. Survivors are visited in the original AST order
      // and still go through `globalFromLiteral`, so the result is unchanged.
      val globalIdentifiers =
          if !sharedCache.hasGlobalScopeInAst(method) then Nil
          else
            val candidates = literalsUnderGlobalAssignments(method)
            if candidates.isEmpty then Nil
            else
              method.ast.isLiteral
                  .filter(lit => candidates.contains(lit.id()))
                  .flatMap(globalFromLiteral)
                  .collectAll[Identifier]
                  .l
      globalIdentifiers
          .foreach { global =>
              firstUsages(global).foreach { identifier =>
                  addEdge(global, identifier, nodeToEdgeLabel(global))
              }
          }
    end addEdgesToCapturedIdentifiersAndParameters

    addEdgesFromEntryNode()
    allNodes.foreach {
        case call: Call                   => addEdgesToCallSite(call)
        case ret: Return                  => addEdgesToReturn(ret)
        case paramOut: MethodParameterOut => addEdgesToMethodParameterOut(paramOut)
        case _                            =>
    }

    addEdgesToCapturedIdentifiersAndParameters()
    addEdgesToExitNode(method.methodReturn)
    addEdgesFromLoneIdentifiersToExit(method)
  end addReachingDefEdges

  /** Ids of the literals in the AST of an assignment, in `method`'s AST, that belongs to a
    * global-scope method - not descending into nested METHODs, where an upward walk from a literal
    * would stop before reaching the assignment.
    */
  private def literalsUnderGlobalAssignments(method: Method): Set[Long] =
    val out  = Set.newBuilder[Long]
    val work = mutable.Stack.empty[AstNode]
    method.ast.isCall
        .filter(c => allAssignmentTypes.contains(c.name))
        .filter(c => Option(c.method).exists(m => GlobalScopeMethodNames.contains(m.name)))
        .foreach(work.push)
    while work.nonEmpty do
      work.pop() match
        case _: Method    =>
        case lit: Literal => out += lit.id()
        case node         => node._astOut.foreach { case c: AstNode => work.push(c); case _ => }
    out.result()

  private def addEdge(fromNode: StoredNode, toNode: StoredNode, variable: String = "")(implicit
    dstGraph: DiffGraphBuilder
  ): Unit =
    if fromNode.isInstanceOf[Unknown] || toNode.isInstanceOf[Unknown] then
      return

    (fromNode, toNode) match
      case (parentNode: CfgNode, childNode: CfgNode)
          if EdgeValidator.isValidEdge(childNode, parentNode) =>
          dstGraph.addEdge(
            fromNode,
            toNode,
            EdgeTypes.REACHING_DEF,
            PropertyNames.VARIABLE,
            variable
          )
      case _ =>

  /** There are a few node types that (a) are not to be considered in the DDG, or (b) are not
    * standalone DDG nodes, or (c) have a special meaning in the DDG. This function indicates
    * whether the given node is just a regular DDG node instead.
    */
  private def isDdgNode(x: StoredNode): Boolean =
      x match
        case _: Method           => false
        case _: ControlStructure => false
        case _: FieldIdentifier  => false
        case _: JumpTarget       => false
        case _: MethodReturn     => false
        case _                   => true

  private def nodeToEdgeLabel(node: StoredNode): String =
      node match
        case n: MethodParameterIn => n.name
        case n: CfgNode           => n.code
        case _                    => ""
end DdgGenerator

/** Upon calculating reaching definitions, we find ourselves with a set of incoming definitions
  * `in(n)` for each node `n` of the flow graph. This component determines those of the incoming
  * definitions that are relevant as the value they define is actually used by `n`.
  */
private class UsageAnalyzer(
  problem: DataFlowProblem[StoredNode, mutable.BitSet],
  in: Map[StoredNode, Set[Definition]],
  nestedContainers: Boolean = false
):

  val numberToNode: Map[Definition, StoredNode] =
      problem.flowGraph.asInstanceOf[ReachingDefFlowGraph].numberToNode

  // `*p` reaches the object `p` points to as `p[0]` does: a read of `*p` uses `p`'s definition,
  // and a write through `*p` reaches later uses of `p`
  private val containerSet =
      Set(
        Operators.fieldAccess,
        Operators.indexAccess,
        Operators.indirectIndexAccess,
        Operators.indirectFieldAccess,
        Operators.indirection
      )
  private val indirectionAccessSet = Set(Operators.addressOf, Operators.indirection)
  val usedIncomingDefs: Map[StoredNode, Map[StoredNode, Set[Definition]]] = initUsedIncomingDefs()

  /** Only `Call`, `Return` and `MethodParameterOut` nodes ever have non-empty `uses` (see
    * [[uses]]), so only they can have non-empty used-incoming-defs. We therefore compute entries
    * for those nodes alone and default every other node to the empty map - identical to mapping
    * over all nodes (which produced empty maps for the rest) but without allocating an entry, and
    * without calling `uses`, for every identifier/literal/etc. in the method.
    */
  def initUsedIncomingDefs(): Map[StoredNode, Map[StoredNode, Set[Definition]]] =
      in.keys.iterator.collect {
          case node: Call               => node -> usedIncomingDefsForNode(node)
          case node: Return             => node -> usedIncomingDefsForNode(node)
          case node: MethodParameterOut => node -> usedIncomingDefsForNode(node)
      }.toMap.withDefaultValue(Map.empty[StoredNode, Set[Definition]])

  private def usedIncomingDefsForNode(node: StoredNode): Map[StoredNode, Set[Definition]] =
      uses(node).map { use =>
          use -> in(node).filter { inElement =>
            val inElemNode = numberToNode(inElement)
            isUsing(use, inElemNode)
          }
      }.toMap

  def isUsing(use: StoredNode, inElemNode: StoredNode): Boolean =
      sameVariable(use, inElemNode) || isContainer(use, inElemNode) || isPart(
        use,
        inElemNode
      ) || isAlias(use, inElemNode)

  /** Determine whether the node `use` describes a container for `inElement`, e.g., use = `ptr`
    * while inElement = `ptr->foo`, or use = `buf` while inElement = `buf + len`: a call that writes
    * through a pointer moved by pointer arithmetic (`strncat(buf + len, src, n)`) writes the object
    * the pointer operand points to.
    */
  private def isContainer(use: StoredNode, inElement: StoredNode): Boolean =
      inElement match
        case call: Call if containerSet.contains(call.name) =>
            call.argument.headOption.exists { base =>
                nodeToString(use) == nodeToString(base)
            }
        case call: Call =>
            pointerOperandOf(call).exists { base =>
              val written = nodeToString(base)
              nodeToString(use) == written || addressOrCastOf(use).exists(
                nodeToString(_) == written
              )
            }
        case _ => false

  /** The pointer a use passes on unchanged but for its address or type: `&buf` (a callee that is
    * given `&buf` reads the buffer through `*p`) or `(char *)buf`.
    */
  private def addressOrCastOf(use: StoredNode): Option[Expression] =
      use match
        case c: Call if c.name == Operators.addressOf => c.argument.l.headOption
        case c: Call if c.name == Operators.cast =>
            c.argument.l.lastOption.flatMap(inner => addressOrCastOf(inner).orElse(Some(inner)))
        case _ => None

  /** The pointer operand of a pointer addition or subtraction, as the C/C++ frontend tags it
    * (`add:<i>`/`sub:<i>`, the argument index of the pointer), also under casts (`(char *)(buf +
    * len)`); the distance between two pointers (`diff`) points to no object.
    */
  private def pointerOperandOf(call: Call): Option[Expression] =
      if call.name == Operators.cast then
        call.argument.l.lastOption.collect { case c: Call => c }.flatMap(pointerOperandOf)
      else
        call.tag.nameExact(Defines.PointerArithmeticTag).value.collectFirst {
            case v if v.startsWith("add:") || v.startsWith("sub:") => v.drop(4).toIntOption
        }.flatten.flatMap(call.argumentOption)

  /** Determine whether `use` is a part of `inElement`, e.g., use = `argv[0]` while inElement =
    * `argv`
    */
  private def isPart(use: StoredNode, inElement: StoredNode): Boolean =
      use match
        case call: Call if containerSet.contains(call.name) =>
            val bases = call.argument.headOption.toList.flatMap(baseChain)
            inElement match
              case param: MethodParameterIn =>
                  bases.exists(base => nodeToString(base).contains(param.name))
              case identifier: Identifier =>
                  bases.exists(base => nodeToString(base).contains(identifier.name))
              case _ => false
        case _ => false

  def isContainerAccess(call: Call): Boolean = containerSet.contains(call.name)

  /** The base of a container access, and - for JavaScript - the bases under it: `e.data.html` is a
    * part of `e` as much as `e.data` is. Elsewhere only the immediate base counts, as it always
    * has.
    */
  private def baseChain(base: Expression): List[Expression] =
      base match
        case inner: Call if nestedContainers && containerSet.contains(inner.name) =>
            base :: inner.argument.headOption.toList.flatMap(baseChain)
        case _ => List(base)

  private def isAlias(use: StoredNode, inElement: StoredNode): Boolean =
      use match
        case useCall: Call =>
            inElement match
              case inCall: Call =>
                  val (useBase, useAccessPath) = toTrackedBaseAndAccessPathSimple(useCall)
                  val (inBase, inAccessPath)   = toTrackedBaseAndAccessPathSimple(inCall)
                  useBase == inBase && useAccessPath.matchAndDiff(
                    inAccessPath.elements
                  )._1 == MatchResult.EXACT_MATCH
              case _ => false
        case _ => false

  def uses(node: StoredNode): Set[StoredNode] =
    val n: Set[StoredNode] = node match
      case ret: Return                  => ret.astChildren.collect { case x: Expression => x }.toSet
      case call: Call                   => call.argument.toSet
      case paramOut: MethodParameterOut => Set(paramOut)
      case _                            => Set()
    n.filterNot(_.isInstanceOf[FieldIdentifier])

  /** Compares arguments of calls with incoming definitions to see if they refer to the same
    * variable
    */
  private def sameVariable(use: StoredNode, inElement: StoredNode): Boolean =
      inElement match
        case param: MethodParameterIn =>
            nodeToString(use).contains(param.name) || nodeToString(use).contains(param.code)
        case call: Call if indirectionAccessSet.contains(call.name) =>
            call.argumentOption(1).exists(x => nodeToString(use).contains(x.code))
        case call: Call =>
            nodeToString(use).contains(call.code)
        case identifier: Identifier =>
            nodeToString(use).contains(identifier.name) || nodeToString(use).contains(
              identifier.code
            )
        case _ => false

  private def nodeToString(node: StoredNode): Option[String] =
      node match
        case ident: Identifier     => Some(ident.name)
        case exp: Expression       => Some(exp.code)
        case p: MethodParameterIn  => Some(p.name)
        case p: MethodParameterOut => Some(p.name)
        case _                     => None
end UsageAnalyzer
