package io.appthreat.jssrc2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.codepropertygraph.generated.nodes.{Identifier, Method, MethodRef}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** A pass that identifies assignments of closures to constants and updates `METHOD` nodes
  * accordingly.
  */
object ConstClosurePass:
  /** A Svelte snippet block, as astgen emits it: an assignment of an arrow function to the
    * snippet's name, whose code is the template source. The range starts at the snippet *name*
    * rather than at `{#snippet`, so the closing tag is the reliable anchor.
    */
  private[passes] val SvelteSnippetPattern: String = "(?s).*\\{/snippet\\}"

class ConstClosurePass(cpg: Cpg) extends CpgPass(cpg):

  import ConstClosurePass.SvelteSnippetPattern

  // Keeps track of how many times an identifier has been on the LHS of an assignment, by name
  private lazy val identifiersAssignedCount: Map[String, Int] =
      cpg.assignment.target.collectAll[Identifier].name.groupCount

  override def run(diffGraph: DiffGraphBuilder): Unit =
    handleConstClosures(diffGraph)
    handleSvelteSnippetClosures(diffGraph)
    handleClosuresDefinedAtExport(diffGraph)
    handleClosuresAssignedToMutableVar(diffGraph)

  private def handleConstClosures(diffGraph: DiffGraphBuilder): Unit =
      for
        assignment      <- cpg.assignment
        name            <- assignment.filter(_.code.startsWith("const ")).target.isIdentifier.name
        methodRef       <- assignment.start.source.isMethodRef
        method          <- methodRef.referencedMethod
        enclosingMethod <- assignment.start.method.fullName
      do
        updateClosures(diffGraph, method, methodRef, enclosingMethod, name)

  /** Svelte snippets. `{#snippet row(item)}...{/snippet}` is emitted by astgen as an assignment of
    * an arrow function to the snippet's name, so it is exactly the const-closure shape - except
    * that the assignment's `code` is the template source (`row(item)}...{/snippet}`) rather than a
    * `const ` declaration, so `handleConstClosures` skips it and the closure keeps the name
    * `anonymous`. Matching on the template syntax gives snippets the same treatment, which is what
    * makes `{@render row(x)}` resolve to a named method.
    */
  private def handleSvelteSnippetClosures(diffGraph: DiffGraphBuilder): Unit =
      for
        assignment      <- cpg.assignment.code(SvelteSnippetPattern)
        name            <- assignment.start.target.isIdentifier.name
        methodRef       <- assignment.start.source.isMethodRef
        method          <- methodRef.referencedMethod
        enclosingMethod <- assignment.start.method.fullName
      do
        updateClosures(diffGraph, method, methodRef, enclosingMethod, name)

  private def handleClosuresDefinedAtExport(diffGraph: DiffGraphBuilder): Unit =
      for
        assignment <- cpg.assignment
        name <- assignment.filter(
          _.code.startsWith("export")
        ).target.isCall.argument.isFieldIdentifier.canonicalName.l
        methodRef       <- assignment.start.source.ast.isMethodRef
        method          <- methodRef.referencedMethod
        enclosingMethod <- assignment.start.method.fullName
      do
        updateClosures(diffGraph, method, methodRef, enclosingMethod, name)

  private def handleClosuresAssignedToMutableVar(diffGraph: DiffGraphBuilder): Unit =
      // Handle closures assigned to mutable variables
      for
        assignment      <- cpg.assignment
        name            <- assignment.start.code("^(var|let) .*").target.isIdentifier.name
        methodRef       <- assignment.start.source.ast.isMethodRef
        method          <- methodRef.referencedMethod
        enclosingMethod <- assignment.start.method.fullName
      do
        // Conservatively update closures, i.e, if we only find 1 assignment where this variable is on the LHS
        if identifiersAssignedCount.getOrElse(name, -1) == 1 then
          updateClosures(diffGraph, method, methodRef, enclosingMethod, name)

  private def updateClosures(
    diffGraph: DiffGraphBuilder,
    method: Method,
    methodRef: MethodRef,
    enclosingMethod: String,
    name: String
  ): Unit =
    val fullName = s"$enclosingMethod:$name"
    diffGraph.setNodeProperty(methodRef, PropertyNames.METHOD_FULL_NAME, fullName)
    diffGraph.setNodeProperty(method, PropertyNames.NAME, name)
    diffGraph.setNodeProperty(method, PropertyNames.FULL_NAME, fullName)
end ConstClosurePass
