package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*

/** Alpine.js (https://alpinejs.dev). A component registered as `Alpine.data('search', () => ({ q:
  * ..., get highlighted() { ... } }))` is used by name in a page - `<section x-data="search">` -
  * and its template reads its properties by bare name: `x-html="highlighted"`. astgen lowers the
  * page to `var search_data = search()` and those reads to `search_data.highlighted`.
  *
  * The object is followed property by property, so that a getter that sanitises (`get clean() {
  * return DOMPurify.sanitize(this.note) }`) does not carry the taint of a sibling: a data property
  * whose value a source reaches makes the component's own `this.<key>` reads sources; a template
  * read of a property takes that property's source, and a read of a getter or method what it
  * returns. Inline `x-data="{ ... }"` objects need none of this - astgen makes their properties
  * variables of the page.
  */
object AlpineRecognizer extends JsFrameworkRecognizer:

  val name: String = "alpine"

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses("alpinejs") || ctx.project.dependsOn("alpinejs")

  /** Sources and sinks are the DOM's and the templates'; the components are bridged. */
  def run(ctx: JsContext): Unit = ()

  private final case class Component(
    callback: Method,
    properties: Map[String, Expression],
    methods: Map[String, Method]
  )

  /** `Alpine.data(name, callback)`: the object the callback returns, by key. */
  private def components(ctx: JsContext): Map[String, Component] =
      ctx.cpg.call.nameExact("data").l.flatMap { c =>
        val file = c.method.filename
        val onAlpine = receiverOf(c).flatMap(memberPath).exists {
            case List(binding) =>
                binding == "Alpine" || ctx.modules.moduleBindingsOf(file, "alpinejs").contains(
                  binding
                )
            case _ => false
        }
        val name = c.argument.filter(_.argumentIndex == 1).headOption.flatMap(literalValue)
        val cb   = c.argument.filter(_.argumentIndex == 2).headOption.flatMap(callbackMethod)
        (onAlpine, name, cb) match
          case (true, Some(n), Some(m)) =>
              // `({ q: v, get g() {} })`: property writes on the literal's temporary
              val writes = m.ast.isCall.nameExact(Operators.assignment)
                  .filter(_.method.id() == m.id()).l
                  .flatMap { a =>
                      (a.argumentOption(1), a.argumentOption(2)) match
                        case (Some(fa: Call), Some(v))
                            if fieldBase(fa).exists(_.code.startsWith("_tmp_")) =>
                            fieldName(fa).map(_ -> v)
                        case _ => None
                  }
              val (fns, values) = writes.partition((_, v) => callbackMethod(v).nonEmpty)
              Some(n -> Component(
                m,
                values.toMap,
                fns.flatMap((k, v) => callbackMethod(v).map(k -> _)).toMap
              ))
          case _ => None
      }.toMap

  /** Runs with the bridges: a property may hold what another bridge made a source. */
  def bridge(ctx: JsContext): Unit =
    if !applies(ctx) then return
    val byName = components(ctx)
    if byName.isEmpty then return
    byName.foreach { (name, component) =>
      val inner = JsIndexes.methodsUnder(ctx.cpg.graph, component.callback.fullName + ":")
      // this.q inside the component's getters and methods
      component.properties.foreach { (key, value) =>
          MemberTaintBridge.sourceOf(ctx, value).foreach { found =>
            val reads = inner.iterator.flatMap(_.ast.isCall.nameExact(Operators.fieldAccess))
                .filter(fa =>
                    fieldName(fa).contains(key) && fieldBase(fa).exists(_.code == "this") &&
                        !isAssignmentTarget(fa)
                )
            ctx.tagger.tagVia(readChains(reads), found.tag, found.places(value)*)
          }
      }
      // search_data.highlighted in the pages that use the component
      val templateReads = ctx.fieldAccesses.filter(fa =>
          fieldBase(fa).exists(_.code == s"${name}_data") && !isAssignmentTarget(fa)
      )
      templateReads.groupBy(fa => fieldName(fa).getOrElse("")).foreach { (key, reads) =>
        val found = component.properties.get(key).flatMap(v =>
            MemberTaintBridge.sourceOf(ctx, v).map(_ -> (v: StoredNode))
        ).orElse(
          component.methods.get(key).flatMap(m =>
              m.ast.isReturn.astChildren.collect { case e: Expression => e }.l.iterator
                  .flatMap(e => MemberTaintBridge.sourceOf(ctx, e).map(_ -> (e: StoredNode)))
                  .nextOption()
          )
        )
        found.foreach((f, v) => ctx.tagger.tagVia(reads, f.tag, f.places(v)*))
      }
    }
  end bridge
end AlpineRecognizer
