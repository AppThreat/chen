package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Ember Octane / Polaris (https://guides.emberjs.com).
  *
  * Sources: a route's `model(params)` and `beforeModel(transition)` hooks receive the URL; the
  * router service's `currentRoute.queryParams`/`params`; a controller's declared `queryParams` are
  * bound to its fields (`queryParams = ['q']` makes `this.q` the `?q=` value).
  *
  * Sinks: `htmlSafe(x)` and its `trustHTML` alias (`@ember/template`), which mark a string as safe
  * markup for the template to render unescaped. Templates (`{{{x}}}`) are not parsed.
  */
object EmberRecognizer extends JsFrameworkRecognizer:

  val name: String = "ember"

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses("@ember", "ember-source", "@glimmer") || ctx.project.dependsOn(
        "ember-source"
      )

  private val RouteHooks = Set("model", "beforeModel", "afterModel", "redirect")

  def run(ctx: JsContext): Unit =
    val routeFiles = ctx.modules.filesImporting("@ember/routing")
    val hooks = ctx.cpg.method.internal.nameExact(RouteHooks.toSeq*)
        .filter(m => routeFiles.contains(m.filename))
    ctx.tagger.tag(hooks.flatMap(firstParam), INPUT)

    val routerReads = ctx.fieldAccesses.filter(fa =>
        fieldName(fa).exists(f => f == "queryParams" || f == "params") &&
            fieldBase(fa).flatMap(memberPath).exists(_.contains("currentRoute"))
    )
    ctx.tagger.tag(readChains(routerReads), INPUT)

    // controller `queryParams = ['q', 'page']`
    val controllerFiles = ctx.modules.filesImporting("@ember/controller")
    ctx.cpg.call.nameExact(Operators.assignment)
        .filter(a => controllerFiles.contains(a.method.filename))
        .filter(_.argumentOption(1).exists {
            case id: Identifier => id.name == "queryParams"
            case fa: Call       => fieldName(fa).contains("queryParams")
            case _              => false
        })
        .l.foreach { a =>
          val names = a.argumentOption(2).toList.flatMap(_.ast.isLiteral.flatMap(literalValue).l)
          a.method.typeDecl.orElse(enclosingTypeDecl(a.method)).foreach { td =>
              names.foreach { n =>
                val reads = classMethods(td).iterator.flatMap(_.ast.isCall)
                    .nameExact(Operators.fieldAccess).codeExact(s"this.$n")
                    .filterNot(isAssignmentTarget)
                ctx.tagger.tag(readChains(reads), INPUT)
              }
          }
        }

    val trusted = ctx.cpg.call.nameExact("htmlSafe", "trustHTML").filter(c =>
        c.argument.filter(_.argumentIndex == 1).exists(!_.isInstanceOf[Literal])
    )
    ctx.tagger.tag(trusted, HtmlSink*)
  end run
end EmberRecognizer
