package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.{ControlStructureTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

import JsShapes.*
import JsTags.*

/** Validation by a guard: a value used only where a check of it has passed.
  *
  * {{{
  * const destination = ALLOWED.includes(next) ? next : "/";
  * if (!LOCAL_PATH.test(candidate)) return "/";  ...use candidate...
  * if (!isHelpTopic(topic)) throw data("Unknown topic", { status: 404 });  ...use topic...
  * return url.origin === location.origin ? url.href : "/";
  * }}}
  *
  * The dataflow engine follows values, not branches: the `next` in the ternary's first branch is
  * the same value as the request's. Here each guard over a variable is found, the code that runs
  * only once it has passed - a branch of the `if` or the ternary whose condition it is, the right
  * operand of `&&`, or what follows an `if` whose other branch leaves the function - and the
  * variable's reads there are tagged `sanitizer`, so a flow through them is dropped by reachables.
  *
  * A guard is a check that admits only values the code names:
  *   - membership in a constant collection: `LIST.includes(x)`, `SET.has(x)`, `Object.hasOwn(MAP,
  *     x)`, `x in MAP`, `LIST.indexOf(x) !== -1`;
  *   - a regular expression anchored at both ends: `/^[\w-]+$/.test(x)`;
  *   - equality with a constant, or of a URL's origin or host with a constant or the page's own: `x
  *     \=== "a"`, `new URL(x).origin === location.origin`;
  *   - a function whose every return is such a check of its parameter (`isHelpTopic(x)`).
  *
  * Prefix checks (`x.startsWith("/")`) are not guards: `//evil.example` starts with a slash.
  */
object GuardBridge:

  def run(ctx: JsContext): Unit =
    val predicates = mutable.HashMap.empty[Long, Option[Int]]
    val guards     = ctx.cpg.call.l.flatMap(c => guardOf(ctx, c, predicates, 2).map(c -> _))
    val guarded = guards.flatMap { case (c, (names, positive)) =>
        regions(c, positive).flatMap(r => readsIn(r, names, c))
    }
    ctx.tagger.tag(guarded.distinctBy(_.id()).iterator, SANITIZER)
    // The engine carries a ternary's result from the checked variable in its condition - the
    // guarded branch need not be on the path at all - so a ternary that can only produce the
    // checked value or a constant (`ALLOWED.includes(x) ? x : "/"`) is itself the sanitiser.
    val choices = guards.flatMap { case (c, (names, positive)) =>
        checkedChoice(c, names, positive)
    }
    ctx.tagger.tag(choices.distinctBy(_.id()).iterator, SANITIZER)

  /** The ternary a guard decides, when the branch the guard admits yields only the checked value
    * and the other only a constant.
    */
  private def checkedChoice(guard: Call, names: Set[String], positive: Boolean): Option[Call] =
    def yieldsChecked(e: Expression): Boolean =
        stripCasts(e) match
          case id: Identifier => names.contains(id.name)
          case fa: Call if fa.name == Operators.fieldAccess =>
              fieldBase(fa).exists(b => yieldsChecked(b))
          case _ => false
    def isConstant(e: Expression): Boolean = isConstantExpr(e) || isConstantSide(e)
    // through `!`: the polarity flips
    def decided(e: AstNode, pos: Boolean, hops: Int): Option[(Call, Boolean)] =
        if hops > 4 then None
        else
          e.astParent match
            case not: Call if not.name == Operators.logicalNot => decided(not, !pos, hops + 1)
            case cond: Call if cond.name == Operators.conditional && isArg(cond, e, 1) =>
                Some(cond -> pos)
            case _ => None
    decided(guard, positive, 0).filter { (cond, pos) =>
      val (admitted, other) = if pos then (2, 3) else (3, 2)
      cond.argument.filter(_.argumentIndex == admitted).exists(yieldsChecked) &&
      cond.argument.filter(_.argumentIndex == other).forall(isConstant)
    }.map(_._1)
  end checkedChoice

  // ---------------------------------------------------------------------------------------------
  // Guards
  // ---------------------------------------------------------------------------------------------

  /** The variables a call checks, and whether the call being true means they passed. */
  private def guardOf(
    ctx: JsContext,
    c: Call,
    predicates: mutable.HashMap[Long, Option[Int]],
    depth: Int
  ): Option[(Set[String], Boolean)] =
    def arg(i: Int)      = c.argument.filter(_.argumentIndex == i).headOption
    def checked(e: Expr) = Some(rootNames(e)).filter(_.nonEmpty)
    callName(c) match
      case "test" if receiverOf(c).exists(isAnchoredRegex) =>
          arg(1).flatMap(checked).map(_ -> true)
      case "includes" | "has" if receiverOf(c).exists(isConstantCollection) =>
          arg(1).flatMap(checked).map(_ -> true)
      case "hasOwn"
          if receiverOf(c).flatMap(memberPath).contains(List("Object")) &&
              arg(1).exists(isConstantCollection) =>
          arg(2).flatMap(checked).map(_ -> true)
      case "hasOwnProperty" if receiverOf(c).exists(isConstantCollection) =>
          arg(1).flatMap(checked).map(_ -> true)
      case "<operator>.in" if arg(2).exists(isConstantCollection) =>
          arg(1).flatMap(checked).map(_ -> true)
      case Operators.equals | Operators.notEquals | "<operator>.identity" |
          "<operator>.notIdentity" =>
          val positive = c.name == Operators.equals || c.name == "<operator>.identity"
          (arg(1), arg(2)) match
            case (Some(a), Some(b)) =>
                indexCheck(a, b, positive).orElse(indexCheck(b, a, positive)).orElse(
                  if isConstantSide(b) then comparedNames(a).map(_ -> positive)
                  else if isConstantSide(a) then comparedNames(b).map(_ -> positive)
                  else None
                )
            case _ => None
      case Operators.greaterThan | Operators.greaterEqualsThan | Operators.lessThan =>
          (arg(1), arg(2)) match
            case (Some(i: Call), Some(n: Literal))
                if callName(i) == "indexOf" &&
                    receiverOf(i).exists(isConstantCollection) =>
                val found = (c.name, n.code) match
                  case (Operators.greaterThan, "-1")      => Some(true)
                  case (Operators.greaterEqualsThan, "0") => Some(true)
                  case (Operators.lessThan, "0")          => Some(false)
                  case _                                  => None
                for
                  positive <- found
                  names    <- i.argument.filter(_.argumentIndex == 1).headOption.flatMap(checked)
                yield names -> positive
            case _ => None
      case _ if depth > 0 && !c.name.startsWith("<operator>") =>
          // a predicate function of the project: its checked parameter, by index
          predicateFunction(ctx, c).flatMap { m =>
              predicates.getOrElseUpdate(m.id(), checkedParameter(ctx, m, predicates, depth - 1))
                  .flatMap(arg).flatMap(checked).map(_ -> true)
          }
      case _ => None
    end match
  end guardOf

  private type Expr = Expression

  /** `LIST.indexOf(x) !== -1` (or `=== -1`, its negation). */
  private def indexCheck(call: Expr, other: Expr, equal: Boolean): Option[(Set[String], Boolean)] =
      (call, other) match
        case (i: Call, n: Literal)
            if callName(i) == "indexOf" && n.code == "-1" &&
                receiverOf(i).exists(isConstantCollection) =>
            i.argument.filter(_.argumentIndex == 1).headOption.map(rootNames)
                .filter(_.nonEmpty).map(_ -> !equal)
        case _ => None

  /** The parameter index whose value every return of `m` checks, positively. */
  private def checkedParameter(
    ctx: JsContext,
    m: Method,
    predicates: mutable.HashMap[Long, Option[Int]],
    depth: Int
  ): Option[Int] =
    val returns = DataLinkBridge.returnedValues(m)
    val perReturn = returns.map { r =>
        conjuncts(r).flatMap {
            case c: Call => guardOf(ctx, c, predicates, depth).filter(_._2).map(_._1)
            case _       => None
        }.flatten.toSet
    }
    if perReturn.isEmpty then None
    else
      params(m).find(p => perReturn.forall(_.contains(p.name))).map(_.index)

  /** The operands of a chain of `&&` (all of which hold when the chain does). */
  private def conjuncts(e: Expr): List[Expr] =
      e match
        case c: Call if c.name == Operators.logicalAnd => c.argument.l.flatMap(conjuncts)
        case other                                     => List(other)

  /** The project function a call names: the resolved callee, else one of that name in the file or
    * imported by it.
    */
  private def predicateFunction(ctx: JsContext, c: Call): Option[Method] =
      c._callOut.collectFirst { case m: Method if !m.isExternal => m }.orElse {
          val file = c.method.filename
          ctx.predicateFunctions.getOrElseUpdate((file, c.name), namedPredicate(ctx, file, c.name))
      }.filter(m => !m.isExternal && params(m).nonEmpty)

  /** The function `name` that a call in `file` refers to: one of the file, else one it imports. */
  private def namedPredicate(ctx: JsContext, file: String, name: String): Option[Method] =
    JsStats.computed("predicateFunction")
    JsIndexes.methodsInFile(ctx.cpg.graph, file, name).headOption.orElse(
      ctx.modules.resolve(file, name).filter(_.module.startsWith(".")).flatMap { imp =>
        val base = JsModules.resolveRelative(file, imp.module)
        JsIndexes.internalMethodsByName(ctx.cpg.graph, imp.imported)
            .find(m => m.filename == base || m.filename.startsWith(base + "."))
      }
    )

  /** A regular expression literal, or a local holding one, that matches whole strings only. */
  private def isAnchoredRegex(e: Expr): Boolean =
    val code = stripCasts(JsValues.origin(stripCasts(e))) match
      case l: Literal => l.code
      case c: Call if c.code.startsWith("new RegExp(") || c.code.startsWith("RegExp(") =>
          c.argument.isLiteral.headOption.flatMap(literalValue).map(v => s"/$v/").getOrElse("")
      case b: Block if b.code.startsWith("new RegExp(") =>
          b.ast.isLiteral.headOption.flatMap(literalValue).map(v => s"/$v/").getOrElse("")
      case _ => ""
    code.startsWith("/^") && code.replaceAll("/[a-z]*$", "").endsWith("$")

  /** A collection the code spells out: an array, Set or Map literal, an object literal, a
    * `SCREAMING_CASE` constant, or a module constant holding one of those.
    */
  private def isConstantCollection(e: Expr): Boolean =
      stripCasts(JsValues.origin(stripCasts(e))) match
        case id: Identifier =>
            isScreamingCase(id.name) || moduleConstant(id).exists(isLiteralCollection)
        case other => isLiteralCollection(other)

  private def isLiteralCollection(e: Expr): Boolean =
      e.code.trim.matches(
        "(?s)^(\\[|\\{|new (Set|Map|WeakSet)\\(|Object\\.(keys|values|freeze|entries)\\().*"
      )

  /** What a module-level `const` holds, for a read inside a function. */
  private def moduleConstant(id: Identifier): Option[Expr] =
      id.method.file.method.nameExact(":program").headOption
          .flatMap(p =>
              JsIndexes.assignedValues(p, id.name) match
                case single :: Nil => Some(stripCasts(single))
                case _             => None
          )

  private def isScreamingCase(name: String): Boolean =
      name.length > 1 && name.exists(_.isLetter) &&
          name.forall(ch => ch.isUpper || ch.isDigit || ch == '_')

  /** `x as T`, `x satisfies T`, `x!`: the value itself. */
  private def stripCasts(e: Expr): Expr =
      e match
        case c: Call if c.name == Operators.cast =>
            c.argument.l.lastOption.map(stripCasts).getOrElse(e)
        case other => other

  /** A side of a comparison that the attacker does not choose: a literal, a constant, the page's
    * own origin or host, or configuration.
    */
  private def isConstantSide(e: Expr): Boolean =
      stripCasts(e) match
        case _: Literal     => true
        case id: Identifier => isScreamingCase(id.name)
        case c: Call if c.name == Operators.fieldAccess =>
            memberPath(c).exists { path =>
              val owners = Set("location", "window", "self", "globalThis", "document")
              (path.lastOption.exists(Set("origin", "host", "hostname").contains) &&
                  path.dropRight(1).forall(owners.contains)) ||
              path.headOption.contains("process") || c.code.startsWith("import.meta.env.") ||
              path.lastOption.exists(isScreamingCase)
            }
        case _ => false

  /** The variables a compared value stands for: a variable, or a URL's origin or host. */
  private def comparedNames(e: Expr): Option[Set[String]] =
      stripCasts(e) match
        case id: Identifier => Some(Set(id.name))
        case c: Call if fieldName(c).exists(Set("origin", "host", "hostname").contains) =>
            fieldBase(c).map(rootNames).filter(_.nonEmpty)
        case _ => None

  /** The variables an expression is a value of: itself, a URL made from it, or a normalised copy
    * (`x.trim()`, `x.toLowerCase()`, `String(x)`).
    */
  private def rootNames(e: Expr): Set[String] =
      stripCasts(e) match
        case id: Identifier if !id.name.startsWith("_tmp_") =>
            Set(id.name) ++ (JsValues.origin(id) match
              case u if isUrlConstruction(u) => urlArgument(u).map(rootNames).getOrElse(Set.empty)
              case _                         => Set.empty
            )
        case c: Call if fieldName(c).exists(Set("origin", "host", "hostname").contains) =>
            fieldBase(c).map(rootNames).getOrElse(Set.empty)
        case c: Call
            if Set("trim", "toLowerCase", "toUpperCase", "normalize").contains(callName(c)) =>
            receiverOf(c).map(rootNames).getOrElse(Set.empty)
        case c: Call if c.name == "String" =>
            c.argument.filter(_.argumentIndex == 1).headOption.map(rootNames).getOrElse(Set.empty)
        case u if isUrlConstruction(u) => urlArgument(u).map(rootNames).getOrElse(Set.empty)
        case _                         => Set.empty

  private def isUrlConstruction(e: Expr): Boolean = e.code.startsWith("new URL(")

  /** The string a `new URL(raw, base)` parses - lowered to a block around the `new` call. */
  private def urlArgument(e: Expr): Option[Expr] =
      e.ast.isCall.nameExact("<operator>.new").headOption
          .orElse(Option(e).collect { case c: Call => c })
          .flatMap(_.argument.filter(_.argumentIndex == 1).headOption)

  // ---------------------------------------------------------------------------------------------
  // Where a guard holds
  // ---------------------------------------------------------------------------------------------

  /** The AST subtrees that run only once the guard has held: walking up from it through `!`, `&&`
    * and `||` to the `if` or the ternary it decides, tracking whether the enclosing expression
    * being true (`pos`) or false (`neg`) implies the guard held.
    */
  private def regions(guard: Call, positive: Boolean): List[AstNode] =
    val found = mutable.ListBuffer.empty[AstNode]
    def climb(e: AstNode, pos: Boolean, neg: Boolean, hops: Int): Unit =
      if hops > 8 || (!pos && !neg) then return
      e.astParent match
        case not: Call if not.name == Operators.logicalNot => climb(not, neg, pos, hops + 1)
        case and: Call if and.name == Operators.logicalAnd =>
            if isArg(and, e, 1) && pos then
              and.argument.filter(_.argumentIndex == 2).foreach(found += _)
            climb(and, pos, false, hops + 1)
        case or: Call if or.name == Operators.logicalOr =>
            if isArg(or, e, 1) && neg then
              or.argument.filter(_.argumentIndex == 2).foreach(found += _)
            climb(or, false, neg, hops + 1)
        case cond: Call if cond.name == Operators.conditional && isArg(cond, e, 1) =>
            if pos then cond.argument.filter(_.argumentIndex == 2).foreach(found += _)
            if neg then cond.argument.filter(_.argumentIndex == 3).foreach(found += _)
        case cs: ControlStructure
            if cs.controlStructureType == ControlStructureTypes.IF && cs.condition.exists(
              _.id() == e.id()
            ) =>
            val thenBranch = cs.astChildren.order(2).headOption
            val elseBranch = cs.astChildren.order(3).headOption
            if pos then thenBranch.foreach(found += _)
            if neg then elseBranch.foreach(found += _)
            if (neg && thenBranch.exists(exits)) || (pos && elseBranch.exists(exits)) then
              found ++= following(cs)
        // `const ok = check(x)` - where `ok` is tested
        case a: Call if a.name == Operators.assignment && isArg(a, e, 2) =>
            a.argumentOption(1).collect { case v: Identifier => v }.foreach { v =>
                a.method.ast.isIdentifier.nameExact(v.name)
                    .filterNot(_.id() == v.id()).filterNot(isAssignmentTarget)
                    .foreach(use => climb(use, pos, neg, hops + 1))
            }
        case _ =>
      end match
    end climb
    climb(guard, positive, !positive, 0)
    found.toList
  end regions

  private def isArg(parent: Call, child: AstNode, index: Int): Boolean =
      parent.argument.filter(_.argumentIndex == index).exists(_.id() == child.id())

  /** Calls that never return: they throw a response or a redirect (SvelteKit `error`/`redirect`,
    * Next.js `notFound`/`redirect`/`permanentRedirect`/`forbidden`/`unauthorized`).
    */
  private val Throwing =
      Set("error", "redirect", "notFound", "permanentRedirect", "forbidden", "unauthorized")

  /** True when a branch always leaves: it returns, throws, or ends in doing so. */
  private def exits(branch: AstNode): Boolean =
      branch match
        case _: Return                                 => true
        case c: Call if c.name == "<operator>.throw"   => true
        case c: Call if Throwing.contains(callName(c)) => true
        case b: Block =>
            b.astChildren.filterNot(_.isInstanceOf[Local]).l.lastOption.exists(exits)
        case _ => false

  /** The statements after `node` in its block. */
  private def following(node: AstNode): List[AstNode] =
      node.astParent match
        case b: Block =>
            val order = node.order
            b.astChildren.filter(_.order > order).l
        case _ => Nil

  /** The reads of `names` in a region, in the guard's method, that no assignment after the guard
    * can have changed.
    */
  private def readsIn(region: AstNode, names: Set[String], guard: Call): List[Identifier] =
    val method = guard.method
    val reassigned = names.filter(n =>
        JsIndexes.assignedValues(method, n).exists(v =>
            v.lineNumber.zip(guard.lineNumber).exists((a, b) => a.intValue > b.intValue)
        )
    )
    val live = names -- reassigned
    if live.isEmpty then Nil
    else
      (region match
        case id: Identifier => List(id)
        case other          => other.ast.isIdentifier.l
      ).filter(id => live.contains(id.name) && id.method.id() == method.id())
          .filterNot(isAssignmentTarget)
end GuardBridge
