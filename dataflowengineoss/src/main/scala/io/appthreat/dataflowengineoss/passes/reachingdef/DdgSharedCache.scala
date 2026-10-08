package io.appthreat.dataflowengineoss.passes.reachingdef

import io.appthreat.dataflowengineoss.{GlobalScopeMethodNames, identifierToFirstUsages}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Declaration, Identifier, Method}
import io.shiftleft.semanticcpg.language.*

import java.util.concurrent.ConcurrentHashMap

/** Answers [[DdgGenerator]] needs for every method of a pass but that do not depend on the method:
  * share one instance across a pass's parts to compute each of them once per graph instead of once
  * per method. Thread-safe; the parts of a pass run concurrently.
  *
  * Only valid while the AST, REF and CAPTURE edges it reads stay unchanged, which holds for a
  * reaching-definition pass: it adds REACHING_DEF edges only.
  *
  * @param sharedAcrossMethods
  *   false for the per-method instance a [[DdgGenerator]] creates when it is given none: the
  *   graph-wide precomputation of [[hasGlobalScopeInAst]] only pays off when amortised over a pass,
  *   so such an instance answers it from the method's own AST instead.
  */
final class DdgSharedCache(sharedAcrossMethods: Boolean = true):

  private val usagesByDecls = new ConcurrentHashMap[List[Declaration], List[Identifier]]()
  private val firstLastByDecls =
      new ConcurrentHashMap[List[Declaration], List[(Identifier, Identifier)]]()

  /** `identifierToFirstUsages(identifier)`, which is a function of the identifier's declarations
    * alone: the usages captured from them are a walk over the whole AST of every closure that
    * captures the variable, and in a Python `<module>` every function captures the module's
    * variables.
    */
  def firstUsages(identifier: Identifier): List[Identifier] =
    val decls = identifier.refsTo.l
    if decls.isEmpty then Nil
    else
      val cached = usagesByDecls.get(decls)
      if cached != null then cached
      else
        val computed = identifierToFirstUsages(identifier)
        val raced    = usagesByDecls.putIfAbsent(decls, computed)
        if raced != null then raced else computed

  /** The first and the last captured usage per capturing method, as [[DdgGenerator]] pairs them. */
  def firstAndLastUsages(identifier: Identifier): List[(Identifier, Identifier)] =
    val decls = identifier.refsTo.l
    if decls.isEmpty then Nil
    else
      val cached = firstLastByDecls.get(decls)
      if cached != null then cached
      else
        val computed = firstUsages(identifier).groupBy(_.method).values
            .filter(_.nonEmpty)
            .map(x => (x.head, x.last))
            .toList
        val raced = firstLastByDecls.putIfAbsent(decls, computed)
        if raced != null then raced else computed

  @volatile private var globalScopeHolders: Set[Long] = null

  /** Whether a global-scope method (see [[GlobalScopeMethodNames]]) is `method` or lies in its AST.
    *
    * Computed once for the graph by walking up from each global-scope method instead of down the
    * AST of every method: the downward walk was a full traversal of each method's AST, for the
    * overwhelming majority of methods that hold no global scope.
    */
  def hasGlobalScopeInAst(method: Method): Boolean =
    if !sharedAcrossMethods then
      return method.ast.isMethod.exists(m => GlobalScopeMethodNames.contains(m.name))
    var holders = globalScopeHolders
    if holders == null then
      holders = computeGlobalScopeHolders(Cpg(using method.graph()))
      globalScopeHolders = holders
    holders.contains(method.id())

  private def computeGlobalScopeHolders(cpg: Cpg): Set[Long] =
    // Every AST ancestor of a global-scope method, along every AST in-edge: exactly the nodes whose
    // `ast` reaches one.
    val visited = scala.collection.mutable.HashSet.empty[Long]
    val holders = Set.newBuilder[Long]
    val work    = scala.collection.mutable.Stack.empty[AstNode]
    cpg.method.nameExact(GlobalScopeMethodNames*).foreach(work.push)
    while work.nonEmpty do
      val node = work.pop()
      if visited.add(node.id()) then
        if node.isInstanceOf[Method] then holders += node.id()
        node._astIn.foreach {
            case parent: AstNode => work.push(parent)
            case _               =>
        }
    holders.result()
end DdgSharedCache
