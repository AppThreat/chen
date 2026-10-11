package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

import JsShapes.*

/** Carries a source through reactive derivations, which hold the value their callback returns -
  * a flow no call edge carries.
  *
  * `computed(() => route.params.id)` (Vue, Angular), `useMemo` (React), `createMemo` (Solid),
  * `useComputed$` (Qwik), `linkedSignal` (Angular): the wrapper's result is a source when its
  * callback's return value is, and so are its reads in the function that made it and in the
  * closures that capture it. `watch(source, (value) => ...)` hands the watched value to its
  * callback.
  *
  * Captured variables: the dataflow engine links an outer variable to its reads inside closures
  * where the frontend records the capture, but a module-level binding - all of a Vue
  * `<script setup>` block, a plain script's top level - is no closure binding, and its reads inside
  * functions start untainted. A local whose value comes from a source makes its captured reads
  * sources of the same kind. Where the engine does link the capture, the flow from the read is a
  * suffix of the full flow and is deduplicated away by reachables.
  *
  * Repeats until nothing new is found, since a derived value may feed another.
  */
object ReactiveBridge:

  private val Derivations =
      Set("computed", "useMemo", "createMemo", "useComputed$", "linkedSignal", "derived", "toRef")

  private val Watchers = Set("watch")

  private val MaxRounds = 4

  def run(ctx: JsContext): Unit =
    val assignments = ctx.cpg.call.nameExact(Operators.assignment).l.flatMap { a =>
        (a.argumentOption(1), a.argumentOption(2)) match
          case (Some(id: Identifier), Some(v)) if !id.name.startsWith("_tmp_") && id.name != "this" =>
              Some((a.method, id.name, v))
          case _ => None
    }
    if assignments.isEmpty then return
    val done  = mutable.HashSet.empty[(Long, String)]
    var round = 0
    var grew  = true
    while grew && round < MaxRounds do
      grew = false
      round += 1
      assignments.foreach { case (method, name, value) =>
          if !done.contains((method.id(), name)) then
            taintOf(ctx, value).foreach { tagName =>
                done += ((method.id(), name))
                grew = true
                ctx.tagger.tag(capturedReads(ctx, method, name), tagName)
                // A derived value is a new value in its own method too: `const c = computed(...)`
                // and every later `c.value` there start from the wrapper call.
                if isDerivation(value) then ctx.tagger.tag(readsIn(method, name), tagName)
            }
      }
      // watch(source, (value) => ...)
      ctx.cpg.call.nameExact(Watchers.toSeq*).foreach { w =>
          val args = w.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).l
          if args.size >= 2 then
            val tainted = args.head match
              case id: Identifier => readTag(ctx, id)
              case other =>
                  callbackMethod(other).flatMap(returnTaint(ctx, _)).orElse(taintOf(ctx, other))
            tainted.foreach { tagName =>
                val params = callbacksIn(args(1)).flatMap(firstParam)
                if params.exists(p => !ctx.tagger.has(p.id(), tagName)) then
                  grew = true
                  ctx.tagger.tag(params.iterator, tagName)
            }
      }
    end while
  end run

  private def isDerivation(value: Expression): Boolean =
      JsShapes.unwrap(value) match
        case c: Call => Derivations.contains(callName(c))
        case _       => false

  /** The source tag of a value: what reaches it in its method, or - for a reactive derivation - what
    * its callback returns.
    */
  private def taintOf(ctx: JsContext, value: Expression): Option[String] =
      JsShapes.unwrap(value) match
        case c: Call if Derivations.contains(callName(c)) =>
            c.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).headOption
                .flatMap(a => callbackMethod(a).flatMap(returnTaint(ctx, _)).orElse(MemberTaintBridge.sourceTagOf(ctx, a)))
        case _ => MemberTaintBridge.sourceTagOf(ctx, value)

  private def returnTaint(ctx: JsContext, m: Method): Option[String] =
      m.ast.isReturn.astChildren.collect { case e: Expression => e }.l.iterator
          .flatMap(MemberTaintBridge.sourceTagOf(ctx, _)).nextOption()

  private def readTag(ctx: JsContext, id: Identifier): Option[String] =
      Seq(JsTags.INPUT, JsTags.INGRESS).find(t => ctx.tagger.has(id.id(), t))
          .orElse(MemberTaintBridge.sourceTagOf(ctx, id))

  /** Reads of `name` in the functions nested in `method` that capture it. */
  private def capturedReads(ctx: JsContext, method: Method, name: String): Iterator[Identifier] =
    val prefix = method.fullName + ":"
    ctx.cpg.method.fullName(s"${java.util.regex.Pattern.quote(prefix)}.*").l.iterator
        .filterNot(n => declares(n, name))
        .flatMap(n => readsIn(n, name))

  /** Reads of `name` whose method is `m` itself (not a nested one). */
  private def readsIn(m: Method, name: String): Iterator[Identifier] =
      m.ast.isIdentifier.nameExact(name).filter(_.method.id() == m.id()).filterNot(isAssignmentTarget)

  /** A function that has its own `name` - a parameter, or a variable it assigns - shadows the outer
    * one.
    */
  private def declares(m: Method, name: String): Boolean =
      m.parameter.nameExact(name).nonEmpty ||
          m.ast.isCall.nameExact(Operators.assignment).exists(a =>
              a.method.id() == m.id() && a.argumentOption(1).exists {
                case id: Identifier => id.name == name
                case _              => false
              }
          )
end ReactiveBridge
