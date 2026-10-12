package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*

/** Data a framework hands from a producer to a consumer member by member.
  *
  * A route component reads what its data functions returned - `loaderData.incident.body_html`, a
  * SvelteKit page's `data.snippet`, a Pinia store's `session.returnUrl` - and no call site joins the
  * two. Linking the consumer to the producer as a whole (one CALL edge, one tagged object) makes
  * every member of the object as tainted as its most tainted one: a page that renders the
  * sanitised `data.snippetHtml` raw would be reported for the `data.q` beside it.
  *
  * Here a consumer read is followed back to its root and the member path below it - the props
  * parameter and `[loaderData, incident, body_html]` - and the producer's returned object is
  * followed down the same path to the value it holds there. Where a source reaches that value, the
  * read is tagged with the source's kind and where the value came from.
  */
object DataLinkBridge:

  /** Calls that hand on the object they are given member for member. */
  private val Transparent =
      Set("storeToRefs", "toRefs", "toRaw", "unref", "readonly", "reactive", "toValue")

  /** A read's root and the member path below it: `incident.body_html`, after `const { incident } =
    * loaderData` and `{ loaderData }` destructured from the props parameter, is (the parameter,
    * `[loaderData, incident, body_html]`). Temporaries, locals assigned once, literal index reads and
    * the calls in [[Transparent]] are looked through; the root is a parameter (of the method or of
    * one enclosing it), a call, or an identifier nothing more is known about.
    */
  def accessPath(
    e: Expression,
    depth: Int = 10,
    stop: Identifier => Boolean = _ => false
  ): Option[(StoredNode, List[String])] =
      if depth <= 0 then None
      else
        unwrap(e) match
          case fa: Call if fa.name == Operators.fieldAccess =>
              for
                base         <- fieldBase(fa)
                key          <- fieldName(fa)
                (root, path) <- accessPath(base, depth - 1, stop)
              yield (root, path :+ key)
          case ia: Call if ia.name == Operators.indexAccess =>
              for
                base         <- ia.argumentOption(1)
                key          <- ia.argumentOption(2).flatMap(literalValue)
                (root, path) <- accessPath(base, depth - 1, stop)
              yield (root, path :+ key)
          case c: Call if Transparent.contains(c.name) =>
              c.argument.filter(_.argumentIndex == 1).headOption
                  .flatMap(accessPath(_, depth - 1, stop))
          case id: Identifier if stop(id) => Some(id -> Nil)
          case id: Identifier if id.name != "this" =>
              parameterOf(id) match
                case Some(p) => Some(p -> Nil)
                case None =>
                    JsValues.origin(id) match
                      case same: Identifier if same.name == id.name => Some(same -> Nil)
                      case other => accessPath(other, depth - 1, stop)
          case c: Call => Some(c -> Nil)
          case _       => None

  /** The parameter an identifier reads: of its own method, or - read in a closure - of an enclosing
    * method that does not assign the name.
    */
  private def parameterOf(id: Identifier): Option[MethodParameterIn] =
    val own = id.method.parameter.nameExact(id.name).headOption
    if own.nonEmpty || JsIndexes.assignedValues(id.method, id.name).nonEmpty then own
    else
      val segments = id.method.fullName.split(':')
      (segments.length - 1 to 1 by -1).iterator
          .map(n => segments.take(n).mkString(":"))
          .flatMap(prefix => JsIndexes.methodByFullName(id.graph, prefix))
          .map(outer =>
              outer.parameter.nameExact(id.name).headOption match
                case Some(p)                                                       => Some(Some(p))
                case None if JsIndexes.assignedValues(outer, id.name).nonEmpty => Some(None)
                case None                                                          => None
          )
          .collectFirst { case Some(found) => found }
          .flatten

  /** What a function returns. */
  def returnedValues(m: Method): List[Expression] =
      m.ast.isReturn.filter(_.method.id() == m.id()).astChildren.collect { case e: Expression =>
          e
      }.l

  /** Helpers that wrap the data a function returns: React Router's `data(value, init)`, Remix's
    * `json`/`defer`, SvelteKit's `fail(status, data)` (second argument).
    */
  private val DataWrappers = Map("data" -> 1, "json" -> 1, "defer" -> 1, "fail" -> 2)

  /** The values under `path` in `value`: the property of an object literal, through locals with one
    * assignment, conditionals, `await` and the [[DataWrappers]]. Where the code does not spell the
    * member out - a call's result, a spread - the value itself stands for it. A literal without the
    * member holds nothing there.
    */
  def valueAt(value: Expression, path: List[String], depth: Int = 8): List[Expression] =
      if depth <= 0 || path.isEmpty then List(value)
      else
        JsValues.origin(value) match
          case c: Call if DataWrappers.contains(callName(c)) && !c.name.startsWith("<") =>
              c.argument.filter(_.argumentIndex == DataWrappers(callName(c))).l
                  .flatMap(valueAt(_, path, depth - 1))
          case c: Call if c.name == "<operator>.await" =>
              c.argument.l.flatMap(valueAt(_, path, depth - 1))
          case c: Call if c.name == Operators.conditional =>
              c.argument.filter(_.argumentIndex >= 2).l.flatMap(valueAt(_, path, depth - 1))
          case b: Block if isObjectLiteral(b) =>
              objectProperties(b) match
                case Some(props) =>
                    props.get(path.head).toList.flatMap(valueAt(_, path.tail, depth - 1))
                case None => List(b)
          case other => List(other)

  /** The first source behind what `values` hold under `path`, with the value it was found behind.
    */
  def sourceAt(
    ctx: JsContext,
    values: List[Expression],
    path: List[String]
  ): Option[(MemberTaintBridge.Found, Expression)] =
      values.iterator.flatMap(valueAt(_, path))
          .flatMap(v => MemberTaintBridge.sourceOf(ctx, v).map(_ -> v))
          .nextOption()

  /** Where a consumer's member path leads: to what some values - a producer's returns, the props an
    * element passes - hold under a path, or straight to a source kind (a route's `params`).
    */
  enum Link:
    case Values(values: List[Expression], path: List[String])
    case Source(tag: String)

  /** What `producers` return, under `path`. */
  def produced(producers: List[Method], path: List[String]): Link =
      Link.Values(producers.flatMap(returnedValues), path)

  /** The reads in `methods` and the functions nested in them that stand for a value of their own:
    * not a base that a further member read continues, not the right-hand side of a plain local's
    * assignment (the local's reads stand for it), not a written target, and not a method looked up
    * to be called.
    */
  def leafReads(methods: List[Method]): List[Expression] =
    def isPassThrough(e: Expression): Boolean =
        e.astParent match
          case p: Call
              if (p.name == Operators.fieldAccess || p.name == Operators.indexAccess) &&
                  p.argumentOption(1).exists(_.id() == e.id()) =>
              true
          case a: Call if a.name == Operators.assignment =>
              a.argumentOption(2).exists(_.id() == e.id()) &&
              a.argumentOption(1).exists(_.isInstanceOf[Identifier])
          case _ => false
    val all = methods.flatMap(m => m :: nestedMethods(m)).distinctBy(_.id())
    all.flatMap { m =>
      val ids = m.ast.isIdentifier.filter(_.method.id() == m.id())
          .filterNot(id => id.name == "this" || id.name.startsWith("_tmp_"))
          .filterNot(id => m.parameter.nameExact(id.name).nonEmpty)
          .l
      val members = m.ast.isCall.filter(_.method.id() == m.id())
          .nameExact(Operators.fieldAccess, Operators.indexAccess)
          .filter(_._receiverIn.isEmpty)
          .l
      (ids ++ members).filterNot(e => isAssignmentTarget(e) || isPassThrough(e))
    }

  /** Hooks and composables of the project - `use[A-Z]...` functions - that return an object: a
    * caller destructures it and reads one member at a time (`const { latest } = useLiveTicker()`,
    * `latest.headline`). Each read is tagged with the source behind what the function returns
    * under that member. Runs with the bridges.
    */
  def bridgeHookReturns(ctx: JsContext): Unit =
    val hooks = ctx.cpg.method.internal
        .filter(m => m.name.matches("use[A-Z]\\w*"))
        .l
        .filter(m =>
            returnedValues(m).exists {
                case b: Block => isObjectLiteral(b)
                case _        => false
            }
        )
    if hooks.isEmpty then return
    val byName = hooks.groupBy(_.name)
    val calls  = ctx.cpg.call.filter(c => byName.contains(c.name)).l
    val consumers = calls.map(_.method).distinctBy(_.id())
    bridgeReads(
      ctx,
      consumers,
      (root, path) =>
          root match
            case c: Call if path.nonEmpty && byName.contains(c.name) =>
                val file = c.method.filename
                val fns = byName(c.name).filter(fn =>
                    fn.filename == file || ctx.modules.resolve(file, c.name).exists { i =>
                      val module = i.module
                      if module.startsWith(".") then
                        fn.filename.startsWith(JsModules.resolveRelative(file, module))
                      else fn.filename.contains(module.dropWhile(_ != '/'))
                    }
                )
                Option.when(fns.nonEmpty)(produced(fns, path))
            case _ => None
    )
  end bridgeHookReturns

  /** Tags each leaf read in `methods` whose access path `link` maps: with the source behind the
    * produced value, or with the source kind itself. A variable `stop` accepts is a root itself - a
    * prop declared with a default (`export let content = ''`) is whatever the parent passes.
    */
  def bridgeReads(
    ctx: JsContext,
    methods: List[Method],
    link: (StoredNode, List[String]) => Option[Link],
    stop: Identifier => Boolean = _ => false
  ): Unit =
      leafReads(methods).foreach { read =>
          accessPath(read, stop = stop).flatMap(link.tupled).foreach {
              case Link.Source(tag) => ctx.tagger.tag(Iterator(read), tag)
              case Link.Values(values, path) =>
                  sourceAt(ctx, values, path).foreach((found, value) =>
                      ctx.tagger.tagVia(Iterator(read), found.tag, found.places(value)*)
                  )
          }
      }
end DataLinkBridge
