package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Lit web components (https://lit.dev).
  *
  * Sources: reactive properties - `@property()` members and the keys of `static properties` - are
  * set from DOM attributes and by whoever uses the element, and are read as `this.x`.
  *
  * Sinks: the `unsafeHTML`/`unsafeSVG`/`unsafeMathML` directives, which render their argument as
  * markup, and bindings in an `html`/`svg` template that set markup or a URL: `.innerHTML=${x}`,
  * `href=${x}`, `src=${x}` on a frame or script, `on...=${x}` as a string. A tagged template is
  * lowered to `html(<operator>.formatString(quasi, value, quasi, ...))`, so a binding's position is
  * the literal before it; the template call is tagged, being the node the bound value flows into.
  */
object LitRecognizer extends JsFrameworkRecognizer:

  val name: String = "lit"

  private val Packages = Seq("lit", "lit-html", "lit-element", "@lit")

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses(Packages*) || ctx.project.dependsOn(Packages*)

  private val UnsafeDirectives = Set("unsafeHTML", "unsafeSVG", "unsafeMathML")

  /** The end of a template literal that makes the next value markup or a URL. */
  private val DangerousBinding =
      "(?s).*(\\.(innerHTML|outerHTML)|\\b(href|srcdoc|action|formaction|xlink:href)|<(iframe|frame|script|embed|object)\\b[^>]*\\bsrc|\\bon[a-z]+)\\s*=\\s*[\"']?$"

  def run(ctx: JsContext): Unit =
    tagProperties(ctx)
    val litFiles = ctx.modules.filesImporting(Packages*)
    val directives = ctx.cpg.call.nameExact(UnsafeDirectives.toSeq*)
        .filter(c => litFiles.contains(c.method.filename))
    ctx.tagger.tag(directives, HtmlSink*)
    val templates = ctx.cpg.call.nameExact("html", "svg")
        .filter(c => litFiles.contains(c.method.filename))
        .flatMap(_.argument.isCall.nameExact(Operators.formatString))
        .l
    templates.foreach { template =>
      val (dangerous, safe) = boundValues(template).partition(_._2)
      if dangerous.nonEmpty then
        // The template call is where its values meet; tagged only when nothing else is bound
        // in it, or a text interpolation next to the binding would be reported too.
        if safe.isEmpty then ctx.tagger.tag(Iterator(template), HtmlSink*)
        else
          ctx.tagger.tag(dangerous.iterator.map(_._1).collect { case c: Call => c }, HtmlSink*)
          ctx.tagger.tag(
            dangerous.iterator.map(_._1).collect { case i: Identifier => i },
            HtmlSink*
          )
    }
  end run

  /** The values bound in a template, each with whether its position is dangerous. */
  private def boundValues(template: Call): List[(Expression, Boolean)] =
    val parts = template.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).l
    parts.zipWithIndex.collect {
        case (value, i) if !value.isInstanceOf[Literal] =>
            val before = if i > 0 then parts(i - 1) else value
            val dangerous = before match
              case quasi: Literal => literalText(quasi).matches(DangerousBinding)
              case _              => false
            // an unsafe directive is a sink of its own
            val directive = value match
              case c: Call => UnsafeDirectives.contains(c.name)
              case _       => false
            (value, dangerous && !directive)
    }.filterNot((v, _) =>
        v match
          case c: Call => UnsafeDirectives.contains(c.name)
          case _       => false
    )

  private def literalText(l: Literal): String =
      if l.code.length >= 2 && "\"'`".contains(l.code.head) then
        l.code.substring(1, l.code.length - 1)
      else l.code

  /** `@property() x` members, and the keys of `static properties = { x: {...} }` - which need not
    * be declared members at all (Lit creates their accessors at runtime).
    */
  private def tagProperties(ctx: JsContext): Unit =
    val decorated = ctx.cpg.annotation.nameExact("property").astParent.collectAll[Member].l
    ctx.tagger.tag(decorated.iterator, INPUT)
    val fromDecorators = decorated.map(m => (m.typeDecl, m.name))
    val fromStatic = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(a =>
            a.argumentOption(1).exists {
                case id: Identifier => id.name == "properties"
                case fa: Call       => fieldName(fa).contains("properties")
                case _              => false
            }
        )
        .l.flatMap { a =>
          val keys = a.argumentOption(2).toList.flatMap(
            _.ast.isCall.nameExact(Operators.assignment).flatMap(_.argumentOption(1))
                .collect { case fa: Call => fa }.flatMap(fieldName).l
          )
          a.method.typeDecl.orElse(enclosingTypeDecl(a.method)).toList.flatMap(td =>
              keys.map(k => (td, k))
          )
        }
    (fromDecorators ++ fromStatic).distinct.foreach { (td, name) =>
      val reads = classMethods(td).iterator.flatMap(_.ast.isCall)
          .nameExact(Operators.fieldAccess)
          .codeExact(s"this.$name")
          .filterNot(isAssignmentTarget)
      ctx.tagger.tag(readChains(reads), INPUT)
    }
  end tagProperties
end LitRecognizer
