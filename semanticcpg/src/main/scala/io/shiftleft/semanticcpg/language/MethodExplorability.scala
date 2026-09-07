package io.shiftleft.semanticcpg.language

import io.shiftleft.codepropertygraph.generated.nodes.{Method, Return}

/** The two meanings `isExternal` has always carried, made explicit.
  *
  * Across the codebases `isExternal` is used both for ''attribution'' — this is not the user's
  * code; scope output, attribute findings, resolve package identity — and as a proxy for
  * ''opacity'' — the query engine cannot descend into this method, so its permissive call-site
  * default applies. The two coincided as long as every external method was bodyless. They stop
  * coinciding with dependency ingestion modes that parse library code ''with'' its body
  * (`python-deps=full`): a dependency method is then external for attribution and explorable at the
  * same time.
  *
  * Every engine site that keyed on `isExternal` to decide whether to explore a callee belongs on
  * the predicates below, not on the property. Sites that decide how a finding is ''reported''
  * (slicing output, purl attribution, user scoping) keep keying on `isExternal`.
  */
object MethodExplorability:

  /** True when the engine can find real data-flow paths through this method's own statements: an
    * internal method with a body, or an external method parsed with its body. A stub, a bodyless
    * signature and a signature-only `.pyi` stub (`def f() -> str: ...`) are opaque — the engine's
    * permissive call-site default applies to calls to them, exactly as before.
    *
    * The distinction that matters for an external method is the presence of a RETURN statement: the
    * engine descends into a callee by following its `methodReturn`'s reaching definitions, and a
    * body whose only statement is `...` (every typeshed stdlib stub) produces none. Such a method
    * must keep the permissive default or stdlib calls would silently lose every flow the previous
    * approximation found.
    */
  def isExplorable(method: Method): Boolean =
      if !method.isExternal then method.start.isStub.isEmpty
      else hasReturn(method)

  /** True when the backward walk stops at a call site to this method (`TaskSolver` cases 3/4 and
    * the visibility calculation in `Engine.elemForEdge`): every internal method, plus external
    * methods with a body. Internal stubs stop the walk today — an abstract method has no body to
    * walk into, but the call site is still a boundary the walk reports at — so they are included
    * here and excluded from [[isExplorable]], where the permissive default applies to them instead.
    */
  def stopsWalkAtCallSite(method: Method): Boolean =
      !method.isExternal || hasReturn(method)

  /** Does this method's own body contain a RETURN?
    *
    * Both predicates above sit in the query engine's innermost loop - they are asked of every
    * resolved callee at every step of every backward walk - so this must not be a recursive AST
    * descent. `ContainsEdgePass` already materialises exactly the edge needed: METHOD -CONTAINS->
    * every node of the method's own body, stopping at nested METHODs, with RETURN among the
    * destination types. One edge iteration replaces the walk, and it is also the more correct
    * question: a `return` inside a nested function is that function's return, not this one's.
    *
    * The AST fallback covers a graph whose base layer has not run (frontend unit tests build one
    * directly). A method with a body always contains at least its BLOCK, so an empty CONTAINS
    * iterator means the pass never ran - never that the body is empty.
    */
  private def hasReturn(method: Method): Boolean =
    val contained = method._containsOut
    if contained.hasNext then contained.exists(_.isInstanceOf[Return])
    else method.ast.isReturn.nonEmpty
end MethodExplorability
