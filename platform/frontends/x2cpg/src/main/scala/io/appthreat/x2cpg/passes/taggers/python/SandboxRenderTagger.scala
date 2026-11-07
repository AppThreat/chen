package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{
    Call,
    Expression,
    Identifier,
    Literal,
    StoredNode
}
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** `sandbox-render`: template or expression source compiled or evaluated inside the Python process.
  *
  * CPython does not treat an in-process sandbox as a security boundary, and Jinja's sandboxed
  * environments, RestrictedPython and the expression evaluators are all in-process. Rendering
  * source the application does not own through one of them is code execution whatever the
  * environment promises, so every call tagged here also carries `code-execution`.
  *
  * The calls:
  *   - Jinja: `from_string`, `compile_expression` and `template_class` on any `Environment`
  *     (sandboxed or not), the `Template(...)` constructor, and the render family (`render`,
  *     `render_async`, `generate`, `stream`) on a template one of those produced;
  *   - RestrictedPython's `compile_restricted*`, asteval's `Interpreter.eval` and a direct call of
  *     an interpreter instance, simpleeval's `simple_eval` and `SimpleEval.eval`,
  *     `numexpr.evaluate`, and pandas' `eval` and `query` (the module functions and the `DataFrame`
  *     methods).
  *
  * A call whose source argument is a string literal is the application's own template and is not
  * tagged, and a render is not tagged when the template it renders was compiled from a literal.
  * Templates loaded by name through a loader (`get_template`) are the application's files and are
  * not tagged either.
  *
  * Calls are matched on the resolved full name. The one fallback is `from_string` and its siblings
  * on a receiver whose type the recovery could not name (an environment passed in as a parameter),
  * in a file that imports jinja2.
  */
object SandboxRenderTagger:

  private val CompileNames = Set("from_string", "compile_expression", "template_class")
  private val RenderNames  = Set("render", "render_async", "generate", "stream")

  private val JinjaCompile =
      "jinja2(\\.\\w+)*\\.\\w*Environment\\.(from_string|compile_expression|template_class)".r
  private val JinjaTemplate = "jinja2(\\.\\w+)*\\.Template(\\.__init__)?".r

  /** The render family on what a compile call returned: the recovery spells the receiver either as
    * the class (`jinja2.Template.render`) or as the compile call's return value, with or without
    * the `<returnValue>` segment.
    */
  private val JinjaRender =
      ("jinja2(\\.\\w+)*\\.(Template|\\w*Environment\\.(from_string|template_class)" +
          "(\\.<returnValue>)?|Template\\.__init__\\.<returnValue>)\\.(render|render_async|generate|stream)").r

  /** The evaluator entry points, each a module root and the names that take source text. */
  private val Evaluators =
      ("(RestrictedPython(\\.\\w+)*\\.compile_restricted(_exec|_eval|_function)?" +
          "|asteval(\\.\\w+)*\\.Interpreter\\.(eval|__call__)" +
          "|simpleeval(\\.\\w+)*\\.(simple_eval|(SimpleEval|EvalWithCompoundTypes)\\.eval)" +
          "|numexpr(\\.\\w+)*\\.(re_)?evaluate" +
          "|pandas(\\.[\\w<>]+)*\\.(eval|query))").r

  private val EvaluatorNames = Set(
    "compile_restricted",
    "compile_restricted_exec",
    "compile_restricted_eval",
    "compile_restricted_function",
    "eval",
    "simple_eval",
    "evaluate",
    "re_evaluate",
    "query"
  )

  def tagCalls(atom: Cpg, addTag: (String, StoredNode) => Unit): Unit =
    def sink(c: Call): Unit =
      addTag(PythonRecognizerUtil.SANDBOX_RENDER_TAG, c)
      addTag("code-execution", c)

    lazy val importsByFile = PythonRecognizerUtil.importedEntitiesByFile(atom)
    def fileImportsJinja(c: Call): Boolean =
        PythonRecognizerUtil.fileImports(importsByFile, c.method.filename, Set("jinja2"))

    def isCompile(c: Call): Boolean =
        CompileNames.contains(c.name) && (JinjaCompile.matches(c.methodFullName) ||
            receiverOf(c).exists(r => unresolved(r.typeFullName)) && fileImportsJinja(c))
    def isTemplateConstructor(c: Call): Boolean =
        c.name == "Template" && JinjaTemplate.matches(c.methodFullName)

    // The compile calls, and the local each one's template was assigned to (the frontend lowers a
    // chained `env.from_string(src).render()` through a temporary the same way).
    val compiles = atom.call.name((CompileNames + "Template").mkString("|")).l
        .filter(c => isCompile(c) || isTemplateConstructor(c))
    val compiledInto = mutable.HashMap.empty[(Long, String), Call]
    compiles.foreach { c =>
      if !sourceIsLiteral(c) then sink(c)
      assignedTo(c).foreach(name => compiledInto((c.method.id, name)) = c)
    }

    atom.call.name(RenderNames.mkString("|")).foreach { c =>
      val compiledFrom = receiverOf(c).flatMap(r => compiledInto.get((c.method.id, r.name)))
      val isRender     = JinjaRender.matches(c.methodFullName) || compiledFrom.isDefined
      if isRender && !compiledFrom.exists(sourceIsLiteral) then sink(c)
    }

    atom.call.name(EvaluatorNames.mkString("|")).foreach { c =>
        if Evaluators.matches(c.methodFullName) && !sourceIsLiteral(c) && hasSource(c) then sink(c)
    }

    // an asteval interpreter instance called directly: `aeval(expr)` is named after the instance
    atom.call
        .filter(c => c.argumentOption(0).isEmpty && hasSource(c) && !sourceIsLiteral(c))
        .filter(c =>
            c.method.ast.isIdentifier.nameExact(c.name).typeFullName("asteval\\.Interpreter.*")
                .nonEmpty
        )
        .foreach(sink)
  end tagCalls

  /** A type the recovery could not name. */
  private def unresolved(t: String): Boolean =
      t.isEmpty || t == "ANY" || t.contains("<unknown>")

  /** The receiver of a member call: argument 0 (keyword arguments carry index -1). */
  private def receiverOf(c: Call): Option[Identifier] =
      c.argumentOption(0).collect { case i: Identifier => i }

  /** The source a compile or evaluator call receives is its first positional argument. */
  private def hasSource(c: Call): Boolean = c.argumentOption(1).isDefined

  private def sourceIsLiteral(c: Call): Boolean =
      c.argumentOption(1).exists(_.isInstanceOf[Literal])

  /** The local a call's result is assigned to, when the call is the right side of an assignment. */
  private def assignedTo(c: Call): Option[String] =
      c._astIn.collectFirst { case a: Call if a.name == Operators.assignment => a }
          .filter(_.argumentOption(2).exists(_.id == c.id))
          .flatMap(_.argumentOption(1))
          .collect { case i: Identifier => i.name }
end SandboxRenderTagger
