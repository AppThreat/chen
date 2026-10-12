package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

import JsShapes.*

/** Carries a source through reactive derivations, which hold the value their callback returns - a
  * flow no call edge carries.
  *
  * `computed(() => route.params.id)` (Vue, Angular), `useMemo` (React), `createMemo` (Solid),
  * `useComputed$` (Qwik), `linkedSignal` (Angular), `useState(key, () => ...)` (Nuxt): the
  * wrapper's result is a source when its callback's return value is, and so is the wrapper CALL
  * ITSELF - a composable that returns a derivation (`return computed(...)`) hands the taint to
  * every caller through its return value. `watch(source, (value) => ...)` hands the watched value
  * to its callback.
  *
  * Captured variables: the dataflow engine links an outer variable to its reads inside closures
  * only within the enclosing method's dependence graph - a walk that starts at a sink inside the
  * closure never crosses that link. A local whose value comes from a source therefore makes its
  * captured reads sources of the same kind.
  *
  * Repeats until nothing new is found, since a derived value may feed another.
  */
object ReactiveBridge:

  private val Derivations = Set(
    "computed",
    "useMemo",
    "createMemo",
    "useComputed$",
    "linkedSignal",
    "derived",
    "toRef",
    // React 19: the state is what the action returned
    "useActionState",
    "useFormState",
    // Nuxt: the state's initial value is what the init callback returns
    "useState"
  )

  def isDerivationCall(c: Call): Boolean = Derivations.contains(callName(c))

  /** The callback a derivation evaluates: its first function-valued argument (`computed(fn)`, and
    * Nuxt's `useState(key, fn)` where the callback is the second argument).
    */
  def derivationCallback(c: Call): Option[Method] =
      c.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).l
          .flatMap(a => callbackMethod(a))
          .headOption

  private val Watchers = Set("watch")

  private val MaxRounds = 4

  /** `computed(() => DOMPurify.sanitize(x))`: a derivation whose callback returns a sanitiser's
    * result holds a sanitised value, and is tagged as that sanitiser - the engine carries a value
    * into the derivation through the variables its callback captures, past the sanitiser inside it.
    */
  private def tagSanitizingDerivations(ctx: JsContext): Unit =
      ctx.cpg.call.filter(isDerivationCall).foreach { d =>
          derivationCallback(d).foreach { cb =>
            val returned = cb.ast.isReturn.astChildren.collect { case c: Call => c }
                .filter(_.method.id() == cb.id()).l
            if returned.nonEmpty && returned.forall(r => JsTags.neutralises(ctx.tagger, r)) then
              // categories this run gave the sanitiser are in the memo, not yet on the node
              val categories = Seq(JsTags.XSS, JsTags.REDIRECT, JsTags.HTTP_CLIENT, "file-io")
                  .map(JsTags.sanitizerFor)
                  .filter(t =>
                      returned.forall(r => ctx.tagger.has(r.id(), t) || r.tag.name.exists(_ == t))
                  )
              ctx.tagger.tag(Iterator(d), (Seq(JsTags.SANITIZER) ++ categories)*)
          }
      }

  def run(ctx: JsContext): Unit =
    tagSanitizingDerivations(ctx)
    tagTaintedDerivationCalls(ctx)
    // A local can only be tainted where its own method holds a source (the search for one stays
    // inside the method) or a derivation, whose callback may.
    val withSources =
        ctx.methodsWithSources ++ ctx.cpg.call.filter(isDerivationCall).map(_.method.id()).toSet
    val assignments = ctx.cpg.call.nameExact(Operators.assignment).filter(a =>
        withSources.contains(a.method.id())
    ).l.flatMap { a =>
        (a.argumentOption(1), a.argumentOption(2)) match
          case (Some(id: Identifier), Some(v))
              if !id.name.startsWith("_tmp_") && id.name != "this" =>
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
            val (tainted, viaDerivation) = taintOf(ctx, value)
            tainted.foreach { found =>
              done += ((method.id(), name))
              grew = true
              // The engine links an outer variable to its reads inside closures only inside
              // the ENCLOSING method's dependence graph; a walk that starts at a sink inside
              // the closure never crosses that edge, so the captured read is a source of its
              // own.
              ctx.tagger.tagVia(capturedReads(ctx, method, name), found.tag, found.places(value)*)
              // A derived value is a new value in its own method too: `const c = computed(...)`
              // and every later `c.value` there start from the wrapper call.
              if viaDerivation then
                ctx.tagger.tagVia(readsIn(method, name), found.tag, found.places(value)*)
            }
      }
      if bridgeCapturedParameters(ctx) then grew = true
      if bridgeStateSetters(ctx) then grew = true
      // watch(source, (value) => ...)
      ctx.cpg.call.nameExact(Watchers.toSeq*).foreach { w =>
        val args = w.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).l
        if args.size >= 2 then
          val tainted = args.head match
            case id: Identifier => readTag(ctx, id)
            case other =>
                callbackMethod(other).flatMap(returnTaint(ctx, _)).orElse(taintOf(ctx, other)._1)
          tainted.foreach { found =>
            val params = callbacksIn(args(1)).flatMap(firstParam)
            if params.exists(p => !ctx.tagger.has(p.id(), found.tag)) then
              grew = true
              ctx.tagger.tagVia(params.iterator, found.tag, (found.at :: found.hops)*)
          }
      }
    end while
  end run

  /** A closure reading a parameter of the function it is nested in - `watchEffect(() =>
    * toValue(orderId))` inside `useOrder(orderId)` - reads what the function's callers pass. The
    * engine does not cross from a parameter into the closures that capture it, so where a source
    * reaches an argument some caller passes, the captured reads are tagged with it. Returns whether
    * anything new was tagged.
    */
  private def bridgeCapturedParameters(ctx: JsContext): Boolean =
    var grew = false
    ctx.cpg.method.internal.filterNot(_.name == ":program").l.foreach { m =>
      lazy val nested = nestedMethods(m)
      params(m).foreach { p =>
          if nested.nonEmpty then
            val reads = capturedReads(ctx, m, p.name).toList
            if reads.nonEmpty && !reads.forall(r => ctx.tagger.has(r.id(), JsTags.INPUT)) then
              callersOf(ctx, m).iterator
                  .flatMap(_.argument.filter(_.argumentIndex == p.index).l)
                  .flatMap(arg => MemberTaintBridge.sourceOf(ctx, arg).map(_ -> arg))
                  .nextOption()
                  .foreach { (found, arg) =>
                    if reads.exists(r => !ctx.tagger.has(r.id(), found.tag)) then grew = true
                    ctx.tagger.tagVia(reads, found.tag, found.places(arg)*)
                  }
      }
    }
    grew
  end bridgeCapturedParameters

  /** `const [html, setHtml] = useState("")`, set from a message handler: the engine has no edge
    * from the setter's argument to the state, so where a source reaches what the setter is called
    * with, the state's reads - in the component and the closures in it - are tagged with it.
    * Returns whether anything new was tagged.
    */
  private def bridgeStateSetters(ctx: JsContext): Boolean =
    var grew = false
    ctx.cpg.call.nameExact(MemberTaintBridge.StateHooks.toSeq*).l.foreach { hook =>
        if MemberTaintBridge.setterCalls(hook).nonEmpty then
          stateVariable(hook).foreach { name =>
              MemberTaintBridge.sourceOf(ctx, hook).foreach { found =>
                val reads = (hook.method :: nestedMethods(hook.method))
                    .filterNot(m => m.id() != hook.method.id() && declares(m, name))
                    .flatMap(m => readsIn(m, name).l)
                if reads.exists(r => !ctx.tagger.has(r.id(), found.tag)) then grew = true
                ctx.tagger.tagVia(reads, found.tag, found.places(hook)*)
              }
          }
    }
    grew

  /** The variable a state hook's value is destructured into: `html` of `_tmp = useState(x); html =
    * _tmp[0]`.
    */
  private def stateVariable(hook: Call): Option[String] =
      hook.astParent match
        case a: Call if a.name == Operators.assignment =>
            a.argumentOption(1).collect { case t: Identifier => t.name }.flatMap { tmp =>
                hook.method.ast.isCall.nameExact(Operators.assignment).l.flatMap { s =>
                    (s.argumentOption(1), s.argumentOption(2)) match
                      case (Some(id: Identifier), Some(ia: Call))
                          if ia.name == Operators.indexAccess && ia.code == s"$tmp[0]" =>
                          Some(id.name)
                      case _ => None
                }.headOption
            }
        case _ => None

  /** The calls of a function: resolved ones, and calls by name from its own file or from a file
    * that imports it relatively or through an alias.
    */
  private def callersOf(ctx: JsContext, fn: Method): List[Call] =
    val resolved = fn._callIn.collect { case c: Call => c }.l ++ ctx.tagger.callSitesOf(fn)
    if resolved.nonEmpty then resolved
    else
      ctx.cpg.call.nameExact(fn.name).l.filter { c =>
        val file = c.method.filename
        file == fn.filename || ctx.modules.resolve(file, fn.name).exists { i =>
          val module = i.module
          if module.startsWith(".") then
            fn.filename.startsWith(JsModules.resolveRelative(file, module))
          else
            (module.startsWith("@/") || module.startsWith("~/") || module.startsWith("$lib/")) &&
            fn.filename.contains(module.dropWhile(_ != '/'))
        }
      }

  /** A derivation call whose callback returns a source is itself a source: the wrapper holds that
    * value. Tagging the call - not only reads of a local it was assigned to - carries the taint out
    * of the defining function, to whatever consumes the composable's return value elsewhere.
    */
  private def tagTaintedDerivationCalls(ctx: JsContext): Unit =
      ctx.cpg.call.filter(isDerivationCall).foreach { d =>
          derivationCallback(d).foreach { cb =>
              returnTaint(ctx, cb).foreach(found =>
                  ctx.tagger.tagVia(Iterator(d), found.tag, (found.at :: found.hops)*)
              )
          }
      }

  private def isDerivation(value: Expression): Boolean =
      JsShapes.unwrap(value) match
        case c: Call => Derivations.contains(callName(c))
        case _       => false

  /** The source tag of a value: what reaches it in its method, or - for a reactive derivation -
    * what its callback returns.
    */
  private def taintOf(
    ctx: JsContext,
    value: Expression
  ): (Option[MemberTaintBridge.Found], Boolean) =
      JsShapes.unwrap(value) match
        case c: Call if Derivations.contains(callName(c)) =>
            val found = c.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).headOption
                .flatMap(a =>
                    callbackMethod(a).flatMap(returnTaint(ctx, _))
                        .orElse(MemberTaintBridge.sourceOf(ctx, a))
                )
            (found, found.nonEmpty)
        case _ =>
            val (_, derived) = MemberTaintBridge.sourceTagThrough(ctx, value)
            (MemberTaintBridge.sourceOf(ctx, value), derived)

  private def returnTaint(ctx: JsContext, m: Method): Option[MemberTaintBridge.Found] =
      m.ast.isReturn.astChildren.collect { case e: Expression => e }.l.iterator
          .flatMap(MemberTaintBridge.sourceOf(ctx, _)).nextOption()

  private def readTag(ctx: JsContext, id: Identifier): Option[MemberTaintBridge.Found] =
      Seq(JsTags.INPUT, JsTags.INGRESS).find(t => ctx.tagger.has(id.id(), t))
          .map(MemberTaintBridge.Found(_, id))
          .orElse(MemberTaintBridge.sourceOf(ctx, id))

  /** Reads of `name` in the functions nested in `method` that capture it. */
  private def capturedReads(ctx: JsContext, method: Method, name: String): Iterator[Identifier] =
      nestedMethods(method).iterator
          .filterNot(n => declares(n, name))
          .flatMap(n => readsIn(n, name))

  /** Reads of `name` whose method is `m` itself (not a nested one). */
  private def readsIn(m: Method, name: String): Iterator[Identifier] =
      m.ast.isIdentifier.nameExact(name).filter(_.method.id() == m.id()).filterNot(
        isAssignmentTarget
      )

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
