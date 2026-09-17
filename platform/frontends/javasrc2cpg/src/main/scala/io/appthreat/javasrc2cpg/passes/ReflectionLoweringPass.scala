package io.appthreat.javasrc2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, EdgeTypes, Operators, PropertyNames}
import io.shiftleft.codepropertygraph.generated.nodes.{
    Call,
    FieldIdentifier,
    Identifier,
    Literal,
    Method,
    TypeDecl
}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable
import scala.jdk.CollectionConverters.*

/** Rewrites Java reflection call sites into ordinary calls on the method they actually reach.
  *
  * Reflection is otherwise a dead end in the graph: `m.invoke(o, tainted)` names
  * `java.lang.reflect.Method.invoke` and nothing else, so the call graph stops there and taint
  * stops with it - even when the target is named by literals a few lines up. That boundary is where
  * plugin dispatchers, `Class.forName` factories and deserialisation gadgets live, so these are
  * exactly the flows worth not dropping.
  *
  * Resolution is intra-procedural and constant-driven, so the pass only ever rewrites a call site
  * whose target it can name outright, and leaves every other one alone:
  *
  *   - a *class handle* is a local assigned from `Class.forName("a.b.C")`, `X.class`, or
  *     `loader.loadClass("a.b.C")`;
  *   - a *method handle* is a local assigned from `handle.getMethod("name", ..)` (or
  *     `getDeclaredMethod`) on a class handle, with a literal method name;
  *   - a *constructor handle* comes from `handle.getConstructor(..)`.
  *
  * A local assigned more than once is skipped rather than guessed at, and a name that matches
  * several overloads is skipped too - both would put an edge on a call site that may never reach
  * the target.
  *
  * Rewriting, rather than only adding a CALL edge, is what makes data flow work without teaching
  * the language-agnostic engine about `java.lang.reflect`. A reflective site passes its arguments
  * boxed in an `Object[]`, so `m.invoke(o, a1)` lowers to `(0: m, 1: o, 2: arrayInitializer(1:
  * a1))` while the target's parameters are `(0: this, 1: a1)`. The pass therefore drops the handle,
  * re-indexes the invocation target to the receiver slot, and lifts the array's elements into the
  * argument slots they were always destined for - after which the call is positionally an ordinary
  * call and every existing consumer (call linkers, data flow, taggers) handles it with no special
  * case. The `code` property keeps the original reflective source text, so findings still point at
  * what the developer wrote.
  *
  * The pass fires only when some call already carries a `java.lang.reflect` (or `Class.forName`)
  * full name, which is how it costs nothing on the vast majority of graphs. That does mean a build
  * whose JDK types went unresolved - no type solver, so the reflective sites keep their unresolved
  * full names - gets no lowering at all, which is the expected answer: with no resolved types there
  * is nothing to resolve the handles against either.
  */
class ReflectionLoweringPass(cpg: Cpg) extends CpgPass(cpg):

  import ReflectionLoweringPass.*

  private lazy val methodsByTypeAndName: Map[(String, String), List[Method]] =
      cpg.method.internal
          .filterNot(_.name.startsWith("<operator>"))
          .l
          .groupBy(m => (m.typeDecl.map(_.fullName).getOrElse(""), m.name))

  /** Every call in the graph, grouped by the method containing it.
    *
    * Built once rather than walking each method's AST: `method.ast` visits every node of the
    * subtree to pick out the calls, and this pass would do that for every internal method and again
    * for every type declaration. Going the other way, each call walks the short path up to its own
    * method instead, and one scan serves both sweeps. (This runs before the overlay that adds
    * CONTAINS edges, so `call.method` takes its AST fallback - still a walk up from one node, not a
    * walk down over all of them.)
    *
    * One deliberate difference from the subtree walk it replaced: a local class declares its
    * TYPE_DECL under the enclosing method, so `enclosing.ast` used to sweep the local class's own
    * method bodies too. Here each of those calls is grouped under the method that actually contains
    * it, which is what the handle resolution wants - a local assigned in the enclosing method is
    * not in scope inside the local class's methods.
    */
  private lazy val callsByMethod: Map[Long, List[Call]] =
      cpg.call.l.groupBy(call => Option(call.method).map(_.id()).getOrElse(-1L))

  private def callsIn(method: Method): List[Call] =
      callsByMethod.getOrElse(method.id(), Nil)

  override def run(dstGraph: DiffGraphBuilder): Unit =
    if cpg.call.methodFullName(ReflectionEntryRegex).isEmpty then return
    cpg.method.internal.foreach(m => lowerWithin(m, dstGraph))
    cpg.typeDecl.internal.foreach(td => lowerFieldHeldProxies(td, dstGraph))

  /** Locals of `calls` assigned exactly once; anything re-assigned is ambiguous and deliberately
    * skipped everywhere it is used below.
    */
  private def singleAssignments(calls: List[Call]): Map[String, Call] =
      calls
          .filter(_.name == Operators.assignment)
          .flatMap { assign =>
              assign.argument.find(_.argumentIndex == 1)
                  .collect { case i: Identifier => i.name -> assign }
          }
          .groupBy(_._1)
          .collect { case (name, List((_, assign))) => name -> assign }

  private def lowerWithin(method: Method, dstGraph: DiffGraphBuilder): Unit =
    val calls = callsIn(method)
    if !calls.exists(c => InvocationNames.contains(c.name) || c.name == NewProxyName) then return

    val singleAssignment = singleAssignments(calls)

    val classHandles  = mutable.Map.empty[String, String]
    val methodHandles = mutable.Map.empty[String, (String, String)]

    // Two sweeps, so a handle may refer to a class handle assigned on any line, not just earlier.
    singleAssignment.foreach { case (name, assign) =>
        rhsCall(assign).flatMap(classHandleType).foreach(classHandles.put(name, _))
    }
    singleAssignment.foreach { case (name, assign) =>
        rhsCall(assign).flatMap(methodHandleTarget(_, classHandles)).foreach(
          methodHandles.put(name, _)
        )
    }

    calls.foreach { call =>
      val target = call.name match
        case InvokeName =>
            receiverName(call)
                .flatMap(methodHandles.get)
                .flatMap { case (typeFullName, methodName) =>
                    soleTarget(typeFullName, methodName)
                }
        case NewInstanceName =>
            // `clazz.newInstance()` names the type directly; `ctor.newInstance(..)` reaches it
            // through a constructor handle that was itself derived from a class handle.
            receiverClassType(call, classHandles)
                .orElse(receiverName(call).flatMap(methodHandles.get).map(_._1))
                .flatMap(soleTarget(_, ConstructorName))
        case _ => None
      target.foreach(rewrite(call, _, dstGraph))
    }

    lowerProxies(method, singleAssignment, calls, dstGraph)
  end lowerWithin

  /** Routes calls made on a JDK dynamic proxy to the invocation handler that actually serves them.
    *
    * `Proxy.newProxyInstance(loader, new Class[]{Service.class}, new Handler())` returns something
    * typed as the interface, and `service.run(x)` then looks like an ordinary interface call with
    * no implementation in the graph - the call graph stops, and so does taint, at the point where
    * every AOP interceptor, mapper and instrumentation wrapper does its work.
    *
    * The handler is named by a constant at the creation site often enough to be worth following:
    * when the third argument is a `new Handler()` (possibly anonymous, possibly held in a local)
    * whose type declares `invoke`, calls on the proxy-typed local are rewritten onto that `invoke`.
    * A proxy held in a field of the class that created it - the dominant shape in real proxy code,
    * since factories return their proxies into fields - is followed the same way, see
    * [[lowerFieldHeldProxies]].
    *
    * The argument shapes do not correspond - `invoke(Object proxy, Method method, Object[] args)`
    * receives the interface method's arguments boxed in its third parameter - so the rewrite maps
    * each argument of the proxied call to the `args` parameter rather than positionally. That is
    * where their values really arrive, and it is why the mapping collects every argument at that
    * parameter's index rather than the first: a two-argument interface method has two arguments
    * landing in `args`, and both are the parameter's callers. What that gives up is positional
    * precision INSIDE the handler - a tainted second argument makes `args[0]` look tainted too -
    * and recovering it would mean synthesising the `Object[]` the runtime builds, which no caller
    * wrote in the source. The receiver is mapped onto `invoke`'s `this`, which at runtime is the
    * handler, not the proxy; the proxy value itself is the result of `newProxyInstance`, which no
    * source ever taints, so the slot carries nothing in practice and stays in the AST for the CFG.
    */
  private def lowerProxies(
    method: Method,
    singleAssignment: Map[String, Call],
    calls: List[Call],
    dstGraph: DiffGraphBuilder
  ): Unit =
    val tdFullName = method.typeDecl.map(_.fullName).getOrElse("")
    val proxyHandlers = singleAssignment.flatMap { case (name, assign) =>
        rhsCall(assign)
            .map(stripCasts)
            .filter(_.name == NewProxyName)
            .flatMap(invocationHandlerOf(_, singleAssignment, tdFullName))
            .map(name -> _)
    }
    if proxyHandlers.isEmpty then return

    calls.foreach { call =>
        receiverName(call)
            .flatMap(proxyHandlers.get)
            .foreach(handler => rewriteProxyCall(call, handler, dstGraph))
    }
  end lowerProxies

  /** Calls on a proxy the class keeps in a field, routed like the local case.
    *
    * A field is a proxy field when every write to it in the declaring type's own methods resolves
    * to the same handler: writes from other classes cannot be seen, so a field that any outside
    * code might reassign (anything non-private, in the worst case) is only rewritten when the class
    * itself never writes anything but the one proxy into it. Real proxy-holder fields are written
    * once in a constructor or field initializer (`this.f = (I) Proxy.newProxyInstance(..)`), which
    * the frontend lowers into an assignment whose left side is exactly `this.f` - a field access on
    * `this`, never a local, so the frontend has already settled the shadowing question. Reads are
    * the same shape: `f.run(x)` and `this.f.run(x)` both lower to a call on `this.f`, and a method
    * that declares its own `f` reads THAT instead, as a plain identifier, which this sweep never
    * touches. Nested and sibling classes are out of scope - their `this` is a different type - and
    * so is a field whose writes disagree, or that is never written in-source at all.
    */
  private def lowerFieldHeldProxies(td: TypeDecl, dstGraph: DiffGraphBuilder): Unit =
    val methods = td.method.internal.l
    val calls   = methods.flatMap(callsIn)
    if !calls.exists(_.name == NewProxyName) then return

    val memberNames = td.member.name.l.toSet

    // `this.f = rhs` for a field f declared by this type: every write, from any of its methods.
    val writesByField: Map[String, List[Call]] = calls
        .filter(_.name == Operators.assignment)
        .flatMap { assign =>
            thisFieldAccessAt(assign, 1).map(_.canonicalName -> assign)
        }
        .filter((field, _) => memberNames.contains(field))
        .groupBy(_._1)
        .map((field, pairs) => field -> pairs.map(_._2))

    // A field qualifies only when every one of its writes carries the same handler; a field that
    // is ever written with anything else (a setter's `this.f = null`, say) is left alone.
    // A constructor that creates several proxy fields would otherwise have its calls swept once
    // per field; the assignments it makes are the same set every time.
    val assignmentsByMethod = mutable.Map.empty[Long, Map[String, Call]]

    val proxyFields: Map[String, Method] = writesByField.flatMap { case (field, writes) =>
        val handlers = writes.map { write =>
          val enclosing = write.method
          val assignments = assignmentsByMethod.getOrElseUpdate(
            enclosing.id(),
            singleAssignments(callsIn(enclosing))
          )
          rhsCall(write)
              .map(stripCasts)
              .filter(_.name == NewProxyName)
              .flatMap(invocationHandlerOf(
                _,
                assignments,
                enclosing.typeDecl.map(_.fullName).getOrElse("")
              ))
        }
        handlers.collectFirst { case Some(handler) => handler } match
          case Some(first) if handlers.forall(_.exists(isSameInvoke(_, first))) =>
              Some(field -> first)
          case _ => None
    }
    if proxyFields.isEmpty then return

    // `calls` is already every call of every method of this type.
    calls.foreach { call =>
        receiverThisFieldAccess(call)
            .flatMap(access => proxyFields.get(access.canonicalName))
            .foreach(handler => rewriteProxyCall(call, handler, dstGraph))
    }
  end lowerFieldHeldProxies

  /** The field a receiver reads, when it is `this.f` - the shape both `f.run(x)` and
    * `this.f.run(x)` lower to when no local named `f` shadows the field.
    */
  private def receiverThisFieldAccess(call: Call): Option[FieldIdentifier] =
      call.receiver.collectAll[Call].headOption.flatMap(thisFieldAccess)

  private def thisFieldAccessAt(assign: Call, index: Int): Option[FieldIdentifier] =
      assign.argument.find(_.argumentIndex == index).collect { case c: Call => c }.flatMap(
        thisFieldAccess
      )

  private def thisFieldAccess(access: Call): Option[FieldIdentifier] =
      if access.name != Operators.fieldAccess then None
      else
        access.argument.l match
          case (receiver: Identifier) :: (field: FieldIdentifier) :: Nil
              if receiver.code == "this" =>
              Some(field)
          case _ => None

  /** `(Service) expr` and `expr` alike yield the call the cast wraps. */
  private def stripCasts(call: Call): Call =
      if call.name == Operators.cast then
        call.argument.collectAll[Call].find(_.argumentIndex == 2).map(stripCasts).getOrElse(call)
      else call

  /** The `invoke` method of the handler passed as `newProxyInstance`'s third argument.
    *
    * Three shapes name a handler outright, in order of how exactly they name it:
    *
    *   - `new Handler(...)` - including `new InvocationHandler() { .. }`, whose body the frontend
    *     lifts into an `Enclosing$N` type that inherits the base and carries the creation
    *     expression's line number; the anonymous subclass of that base, in that type, on that line,
    *     is the class this expression created, and its `invoke` overrides the base's;
    *   - a local, resolved from the single `new X()` it was assigned - the `alloc` on the right
    *     side names the exact instantiated type even when the local is declared as the interface
    *     (`InvocationHandler h = new Handler()`) - and never from a right side that could name
    *     several types, nor from the local's declared type, which a subclass assignee can override;
    *   - `this`, for the shape where the enclosing class is its own handler.
    *
    * Anything else - a parameter, a field read, a factory call, a right side chosen by a branch -
    * names no single handler, and the creation site is left exactly as it was.
    */
  private def invocationHandlerOf(
    newProxyCall: Call,
    singleAssignment: Map[String, Call],
    enclosingTypeDecl: String
  ): Option[Method] =
    val thirdArg = newProxyCall.argument.find(_.argumentIndex == 3)
    thirdArg.collect { case c: Call if c.name == ConstructorName => c }.orElse(
      thirdArg.collect {
          // `new Handler()` lowers to a block whose `<init>` is a direct child, next to the alloc.
          case block: io.shiftleft.codepropertygraph.generated.nodes.Block =>
              block.astChildren.collectAll[Call].nameExact(ConstructorName).headOption
      }.flatten
    ) match
      case Some(ctor) =>
          ctorTypeOf(ctor).flatMap(handlerMethod(_, ctor.lineNumber, enclosingTypeDecl))
      case None =>
          thirdArg.collect { case identifier: Identifier =>
              if identifier.code == "this" then
                Option(identifier.typeFullName)
                    .filter(t => t.nonEmpty && t != "ANY")
                    .flatMap(soleTarget(_, InvokeName))
              else handlerLocalType(identifier, singleAssignment, enclosingTypeDecl)
          }.flatten
  end invocationHandlerOf

  private def ctorTypeOf(ctor: Call): Option[String] =
      Option(ctor.methodFullName)
          .filter(_.contains(s".$ConstructorName"))
          .map(_.takeWhile(_ != ':').stripSuffix(s".$ConstructorName"))

  /** A handler local's `invoke`, from the one `new X()` it was assigned.
    *
    * The right side of `h = new Handler()` lowers to the `alloc` of the object, which carries the
    * exact instantiated type - `Base h = new Sub()` is a `Sub` - so the assignment names the type
    * that actually serves the invocation, whatever interface the local was declared as. A right
    * side of any other shape (a ternary, a factory call, another local) names no single type, and
    * the local's DECLARED type is not consulted: a base-typed local can hold a subclass whose
    * `invoke` overrides the base's, and an edge to a body that never runs is worse than none.
    */
  private def handlerLocalType(
    identifier: Identifier,
    singleAssignment: Map[String, Call],
    enclosingTypeDecl: String
  ): Option[Method] =
      singleAssignment.get(identifier.name).flatMap(rhsCall(_)).map(stripCasts).flatMap {
          case c: Call if c.name == Operators.alloc =>
              Option(c.typeFullName)
                  .filter(t => t.nonEmpty && t != "ANY")
                  .flatMap(t => handlerMethod(t, c.lineNumber, enclosingTypeDecl))
          case c: Call if c.name == ConstructorName =>
              ctorTypeOf(c).flatMap(t => handlerMethod(t, c.lineNumber, enclosingTypeDecl))
          case _ => None
      }

  /** Whether two `invoke` methods are the same one, by the properties that identify a method. */
  /** Java method full names carry the signature (`Handler.invoke:java.lang.Object(..)`), so this is
    * identity, not a name match that overloads could confuse.
    */
  private def isSameInvoke(a: Method, b: Method): Boolean =
      a.fullName == b.fullName

  /** The `invoke` a `new X(...)` expression's handler resolves to.
    *
    * An anonymous creation types its constructor after the base - `InvocationHandler.<init>` - so
    * the base alone names no body. The frontend records the lifted body's class with the creation
    * expression's line, which identifies it among the enclosing type's anonymous subclasses of that
    * base: that class's `invoke` is the one this site runs, and it is preferred over any base
    * `invoke`, which an anonymous creation overrides. Zero or several matches on the line, and the
    * site is left alone rather than guessed at.
    */
  private def handlerMethod(
    handlerType: String,
    creationLine: Option[Integer | Null],
    enclosingTypeDecl: String
  ): Option[Method] =
      anonymousInvoke(handlerType, creationLine, enclosingTypeDecl)
          .orElse(soleTarget(handlerType, InvokeName))

  private def anonymousInvoke(
    baseType: String,
    creationLine: Option[Integer | Null],
    enclosingTypeDecl: String
  ): Option[Method] =
      creationLine match
        case None       => None
        case Some(null) => None
        case Some(line) =>
            cpg.typeDecl.fullNameExact(enclosingTypeDecl).astChildren.isTypeDecl.l
                .filter(anon =>
                    anon.inheritsFromTypeFullName.contains(baseType)
                        && anon.lineNumber.contains(line)
                )
                .flatMap(_.method.nameExact(InvokeName).l)
                .distinct match
              case List(single) => Some(single)
              case _            => None

  private def rewriteProxyCall(call: Call, handler: Method, dstGraph: DiffGraphBuilder): Unit =
    dstGraph.setNodeProperty(call, PropertyNames.NAME, handler.name)
    dstGraph.setNodeProperty(call, PropertyNames.METHOD_FULL_NAME, handler.fullName)
    dstGraph.setNodeProperty(call, PropertyNames.SIGNATURE, handler.signature)
    dstGraph.setNodeProperty(call, PropertyNames.DISPATCH_TYPE, DispatchTypes.DYNAMIC_DISPATCH)
    // Everything the interface method was passed arrives in `invoke`'s `args` array, which is its
    // third declared parameter - index 3 once `this` is counted.
    call.argument.filter(_.argumentIndex > 0).foreach { argument =>
        dstGraph.setNodeProperty(argument, PropertyNames.ARGUMENT_INDEX, ProxyArgsParameterIndex)
    }

  /** The single in-source method of that type with that name, or None when there is no match or
    * more than one overload to choose between.
    */
  private def soleTarget(typeFullName: String, name: String): Option[Method] =
      methodsByTypeAndName.get((typeFullName, name)).collect { case List(single) => single }

  /** Turn the reflective call site into a direct call on `target`, see the class comment. */
  private def rewrite(call: Call, target: Method, dstGraph: DiffGraphBuilder): Unit =
    val isInvoke = call.name == InvokeName

    dstGraph.setNodeProperty(call, PropertyNames.NAME, target.name)
    dstGraph.setNodeProperty(call, PropertyNames.METHOD_FULL_NAME, target.fullName)
    dstGraph.setNodeProperty(call, PropertyNames.SIGNATURE, target.signature)
    dstGraph.setNodeProperty(call, PropertyNames.DISPATCH_TYPE, DispatchTypes.DYNAMIC_DISPATCH)

    // The handle (`m` in `m.invoke(..)`) is no longer an argument of anything - it stays in the AST
    // and the CFG, because it is still evaluated, but it is not passed to the target.
    call.outE(EdgeTypes.ARGUMENT, EdgeTypes.RECEIVER).asScala
        .filter(e => isHandle(e.inNode(), call))
        .foreach(dstGraph.removeEdge)

    // `invoke`'s first argument is the object the target runs on, i.e. its `this`.
    if isInvoke then
      call.argument.find(_.argumentIndex == 1).foreach { self =>
        dstGraph.setNodeProperty(self, PropertyNames.ARGUMENT_INDEX, 0)
        dstGraph.addEdge(call, self, EdgeTypes.RECEIVER)
      }

    // The boxed `Object[]` of reflective arguments is replaced by its elements, whose indices inside
    // the array are already the parameter positions they feed.
    argumentArray(call).foreach { array =>
      array.outE(EdgeTypes.ARGUMENT).asScala.foreach(dstGraph.removeEdge)
      call.outE(EdgeTypes.ARGUMENT).asScala
          .filter(_.inNode() == array)
          .foreach(dstGraph.removeEdge)
      array.astChildren.foreach(child => dstGraph.addEdge(call, child, EdgeTypes.ARGUMENT))
    }
  end rewrite

  private def isHandle(node: overflowdb.Node, call: Call): Boolean =
      node match
        case i: Identifier => i.argumentIndex == 0
        case _             => false

  private def argumentArray(call: Call): Option[Call] =
      call.argument.collectAll[Call].find(_.name == Operators.arrayInitializer)

  private def rhsCall(assign: Call): Option[Call] =
      assign.argument.find(_.argumentIndex == 2).collect { case c: Call => c }

  private def classHandleType(call: Call): Option[String] =
      call.name match
        case "forName" | "loadClass" => literalArg(call, 1).map(stripQuotes)
        case Operators.fieldAccess   =>
            // `X.class` lowers to a field access whose field identifier is `class`. The receiver's
            // resolved type names the class - its `code` is only what the source wrote, which for a
            // nested or imported class is not the full name the graph is indexed by.
            Option.when(call.argument.l.lastOption.exists(_.code == "class")) {
                call.argument.l.headOption.flatMap {
                    case i: Identifier if i.typeFullName.nonEmpty && i.typeFullName != "ANY" =>
                        Some(i.typeFullName)
                    case other => Option(other.code)
                }
            }.flatten
        case _ => None

  private def methodHandleTarget(
    call: Call,
    classHandles: mutable.Map[String, String]
  ): Option[(String, String)] =
      call.name match
        case "getMethod" | "getDeclaredMethod" =>
            for
              typeFqn <- receiverClassType(call, classHandles)
              name    <- literalArg(call, 1).map(stripQuotes)
            yield (typeFqn, name)
        case "getConstructor" | "getDeclaredConstructor" =>
            receiverClassType(call, classHandles).map((_, ConstructorName))
        case _ => None

  /** The type a reflective member call is made on, whether it goes through a local holding a class
    * handle (`c.getMethod(..)`) or names the class inline (`Holder.class.getConstructor(..)`,
    * `Class.forName("a.b.C").newInstance()`).
    */
  private def receiverClassType(
    call: Call,
    classHandles: mutable.Map[String, String]
  ): Option[String] =
      receiverExpr(call).flatMap {
          case i: Identifier => classHandles.get(i.name)
          case c: Call       => classHandleType(c)
          case _             => None
      }

  private def receiverExpr(call: Call)
    : Option[io.shiftleft.codepropertygraph.generated.nodes.Expression] =
      call.receiver.headOption.orElse(call.argument.find(_.argumentIndex == 0))

  /** The name of the identifier a member call is made on (`m` in `m.invoke(..)`). */
  private def receiverName(call: Call): Option[String] =
      receiverExpr(call).collect { case i: Identifier => i.name }

  private def literalArg(call: Call, index: Int): Option[String] =
      call.argument.collectAll[Literal].find(_.argumentIndex == index).map(_.code)

  private def stripQuotes(s: String): String = s.stripPrefix("\"").stripSuffix("\"")
end ReflectionLoweringPass

object ReflectionLoweringPass:
  private val ConstructorName = "<init>"
  private val InvokeName      = "invoke"
  private val NewProxyName    = "newProxyInstance"

  /** `invoke(Object proxy, Method method, Object[] args)` - `args` is parameter 3 after `this`. */
  private val ProxyArgsParameterIndex = 3
  private val NewInstanceName         = "newInstance"
  private val InvocationNames         = Set(InvokeName, NewInstanceName)

  /** Cheap whole-graph guard, so code that never touches reflection never pays for the pass. */
  private val ReflectionEntryRegex =
      "(java\\.lang\\.Class\\.(forName|getMethod|getDeclaredMethod|getConstructor|getDeclaredConstructor|newInstance).*|java\\.lang\\.reflect\\..*)"
