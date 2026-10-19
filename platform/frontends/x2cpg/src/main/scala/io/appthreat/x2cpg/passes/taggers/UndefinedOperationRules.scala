package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** The operations C leaves undefined for some operands, which a bounded model checker asserts at
  * every use (CBMC's `goto_check_c`: division by zero, the undefined shift, the same-object
  * condition on pointer subtraction, and the library's no-overlap precondition). Each rule asks the
  * question of operands whose value the graph establishes - a literal, or an untrusted read - and
  * leaves the rest alone: a divisor that is merely a parameter is the caller's contract, not a
  * defect.
  *
  *   - MS-DIV-001 (CWE-369): a divisor an untrusted read gives, which no dominating guard, no
  *     short-circuit operand and no clamp keeps from being zero; or a divisor whose every
  *     definition is the literal 0.
  *   - MS-SHIFT-001 (CWE-1335): a shift amount whose known value is negative or at least the
  *     promoted operand's width; or one an untrusted read gives, which nothing bounds into [0,
  *     width).
  *   - MS-PTR-001 (CWE-469): a subtraction of two pointers into two different objects (C11 6.5.6p9)
  *     \- a difference that means nothing, usually a length computed against the wrong buffer.
  *   - MS-OVERLAP-001 (CWE-475): a copy the library requires to be between disjoint objects
  *     (`memcpy`, `strcpy`, `strcat`, ...) whose destination and source are the same object at
  *     offsets the copy's length makes overlap. `memmove` allows it.
  */
object UndefinedOperationRules:

  import MemorySafetyFindingPass.*

  private val DivisionOps = Set(
    Operators.division,
    Operators.modulo,
    Operators.assignmentDivision,
    Operators.assignmentModulo
  )

  private val ShiftOps = Set(
    Operators.shiftLeft,
    Operators.arithmeticShiftRight,
    Operators.logicalShiftRight,
    Operators.assignmentShiftLeft,
    Operators.assignmentArithmeticShiftRight,
    Operators.assignmentLogicalShiftRight
  )

  /** The copies whose destination and source must not overlap (C11 7.24.2.1p2, 7.24.2.3p2,
    * 7.24.3.1p2, POSIX for the `p` forms). `memmove` and `bcopy` are defined for overlap.
    */
  private val NoOverlapApis = Set(
    "memcpy",
    "mempcpy",
    "memccpy",
    "strcpy",
    "stpcpy",
    "strncpy",
    "stpncpy",
    "strcat",
    "strncat",
    "wmemcpy",
    "wcscpy",
    "wcsncpy",
    "wcscat",
    "wcsncat"
  )

  /** The string-search calls whose result points into their first argument (the haystack). */
  private val HaystackApis = Set(
    "strchr",
    "strrchr",
    "strstr",
    "memchr",
    "memrchr",
    "strpbrk",
    "strchrnul",
    "rawmemchr",
    "wcschr",
    "wcsrchr",
    "wcsstr",
    "wmemchr",
    "wcspbrk"
  )

  // ---- division -----------------------------------------------------------------------------

  def divisionByZero(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.call.filter(c => DivisionOps.contains(c.name) && !isClassTyped(atom, c)).foreach { div =>
          div.argumentOption(2).collect { case e: Expression => e }.foreach { divisor =>
            // IEEE 754 defines a floating division by a zero constant - it is how a program
            // spells an infinity or a NaN (CBMC checks it only under --float-div-by-zero-check) -
            // until the infinity is converted to an integer, which is undefined (C11 6.3.1.4p1).
            // A zero an untrusted read gives is the CWE-369 defect either way
            val definitelyZero = (!isFloating(div) || convertedToInteger(div)) &&
                definitionValues(divisor).exists(vs => vs.nonEmpty && vs.forall(_ == 0))
            val untrusted =
                !definitelyZero && isUntrusted(divisor) && !isNonZeroTableElement(divisor)
            // a guard that keeps the divisor from zero makes even a zero constant's division
            // dead code: the check is the program's own fix
            if (definitelyZero || untrusted) && !excludesZero(divisor, div) then
              record(div, RuleDivideByZero)
          }
      }

  private def isFloating(c: Call): Boolean =
      (c.typeFullName :: c.argument.l.collect { case e: Expression => typeOf(withoutCasts(e)) })
          .exists(t => FloatingTypes.contains(Option(t).getOrElse("").replace("const ", "").trim))

  /** The division's value is converted to an integer type where it is made: a cast, or the
    * assignment of an integer variable.
    */
  private def convertedToInteger(div: Call): Boolean =
      div._astIn.nextOption() match
        case Some(c: Call) if c.name == Operators.cast => isIntegral(c.typeFullName)
        case Some(a: Call)
            if a.name == Operators.assignment && a.argumentOption(2).exists(_.id() == div.id()) =>
            a.argumentOption(1).exists(lhs => isIntegral(typeOf(lhs)))
        case _ => false

  private def isIntegral(t: String): Boolean =
    val bare = Option(t).getOrElse("").split("\\s+").filterNot(q => q == "const" || q == "volatile")
        .mkString(" ")
    IntegralType.matches(bare)

  private val IntegralType =
      """((un)?signed )?(char|short|int|long|long long|short int|long int|long long int)|(un)?signed|u?int(8|16|32|64|ptr|max)_t|s?size_t|ptrdiff_t""".r

  private val FloatingTypes =
      Set("float", "double", "long double", "float_t", "double_t", "_Float16", "__fp16")

  /** An operator on a class operand is a call of its overload (`Duration /= int64_t`), whose
    * meaning the class gives - not the built-in division. CDT keeps the operator's name when the
    * overload is not in the graph, typed by the class.
    */
  private def isClassTyped(atom: Cpg, c: Call): Boolean =
      (c.typeFullName :: c.argumentOption(1).map(typeOf).toList).exists { raw =>
        val t = Option(raw).getOrElse("").replace("const ", "").stripSuffix("&").trim
        t.nonEmpty && t != "ANY" &&
        atom.typeDecl.fullNameExact(t).exists(td =>
            td.aliasTypeFullName.isEmpty && (td.member.nonEmpty || td.method.nonEmpty)
        )
      }

  /** An element of a table whose every initialiser is a nonzero literal and which nothing writes:
    * `kExp10[15 - n]`. Whatever the index (an out-of-range one is the bounds rules' question), the
    * value is not zero.
    */
  private def isNonZeroTableElement(e: Expression): Boolean =
      withoutCasts(e) match
        case c: Call
            if c.name == Operators.indexAccess || c.name == Operators.indirectIndexAccess =>
            c.argumentOption(1).collect { case i: Identifier => i }.flatMap(tableOf).exists {
                local =>
                  val refs  = local._refIn.collectAll[Identifier].l
                  val inits = refs.flatMap(initialiserOf)
                  val writes =
                      refs.filterNot(r => inits.exists(_._1 == r.id())).exists(writtenThrough)
                  inits.nonEmpty && !writes && inits.forall { case (_, init) =>
                      val elements = init.argument.l.collect { case x: Expression =>
                          withoutCasts(x)
                      }
                      elements.nonEmpty && elements.forall(x => literalNumber(x).exists(_ != 0))
                  }
            }
        case _ => false

  private def tableOf(i: Identifier): Option[Local] =
      i.refsTo.collectFirst { case l: Local => l }.filter(_.typeFullName.contains("["))

  /** `table = { ... }`: the declaration's initialiser list, with the reference it initialises. */
  private def initialiserOf(ref: Identifier): Option[(Long, Call)] =
      ref._astIn.collectFirst { case a: Call if a.name == Operators.assignment => a }
          .filter(_.argumentOption(1).exists(_.id() == ref.id()))
          .flatMap(_.argumentOption(2).collect {
              case init: Call if init.name == Operators.arrayInitializer => ref.id() -> init
          })

  /** A reference that writes the table: assigned, an element assigned or updated, or handed out. */
  private def writtenThrough(ref: Identifier): Boolean =
      ref._astIn.nextOption() match
        case Some(c: Call)
            if c.name == Operators.indexAccess || c.name == Operators.indirectIndexAccess =>
            c._astIn.collectFirst { case p: Call => p }.exists(p =>
                (OverlayFacts.isAssignmentOperator(p.name) || WriteOps.contains(p.name)) &&
                    p.argumentOption(1).exists(_.id() == c.id())
            )
        case Some(c: Call)
            if OverlayFacts.isAssignmentOperator(c.name) || WriteOps.contains(c.name) =>
            c.argumentOption(1).exists(_.id() == ref.id())
        case Some(c: Call) if !c.name.startsWith("<operator>") => true
        case _                                                 => false

  /** Does the program keep `operand` from being zero where `use` reads it? A dominating guard whose
    * branch to the use is impossible with a zero (`if (n == 0) return;`, `if (n > 0) { ... }`), an
    * enclosing `&&`, `||` or `?:` operand position with the same property, or a clamp that replaces
    * a zero before the use (`if (n < 1) n = 1;`).
    */
  private def excludesZero(operand: Expression, use: Call): Boolean =
    val key = OverlayFacts.variableKey(withoutCasts(operand))
    key.exists { k =>
      val guarded = GuardPass.guardingControllers(use).exists { controller =>
          GuardPass.holdsAtOpt(controller, use).exists(h => valueAtZero(controller, k).contains(!h))
      }
      guarded || shortCircuitExcludesZero(use, k) || clampReplacesZero(operand, use, k)
    }

  private def shortCircuitExcludesZero(use: Call, key: String): Boolean =
    var child: StoredNode          = use
    var cursor: Option[StoredNode] = use._astIn.nextOption()
    var found                      = false
    while !found && cursor.isDefined do
      cursor.get match
        case c: Call =>
            val holds: Option[Boolean] = c.name match
              case Operators.logicalAnd if c.argumentOption(2).exists(_.id == child.id) =>
                  Some(true)
              case Operators.logicalOr if c.argumentOption(2).exists(_.id == child.id) =>
                  Some(false)
              case Operators.conditional if c.argumentOption(2).exists(_.id == child.id) =>
                  Some(true)
              case Operators.conditional if c.argumentOption(3).exists(_.id == child.id) =>
                  Some(false)
              case _ => None
            holds.foreach { h =>
                c.argumentOption(1).collect { case e: Expression => e }.foreach { cond =>
                    if valueAtZero(cond, key).contains(!h) then found = true
                }
            }
            child = c
            cursor = c._astIn.nextOption()
        case _ => cursor = None
    end while
    found
  end shortCircuitExcludesZero

  /** `if (C(n)) n = k;` before the use, with k a nonzero literal and C true for a zero: every path
    * on which n could be zero at the test assigns k. The test must dominate the use, and the
    * assignment must be the only statement of its branch that defines n.
    */
  private def clampReplacesZero(operand: Expression, use: Call, key: String): Boolean =
      withoutCasts(operand) match
        case id: Identifier =>
            val defs       = ownDefinitions(id)
            val dominators = use.dominatedBy.map(_.id()).toSet
            defs.exists { d =>
                assignmentOf(d).exists { a =>
                    a.argumentOption(2).exists(rhs => literalNumber(rhs).exists(_ != 0)) &&
                    a.controlledBy.collect { case c: Call => c }.exists { cond =>
                        dominators.contains(cond.id()) &&
                        GuardPass.holdsAtOpt(cond, a).contains(true) &&
                        valueAtZero(cond, key).contains(true)
                    }
                }
            }
        case _ => false

  /** The value a condition takes when the variable `key` names is zero, where that decides it:
    * comparisons of the variable with a number, the variable itself as a truth value, and `!`,
    * `&&`, `||` over them. None when the outcome depends on anything else.
    */
  private def valueAtZero(cond: Expression, key: String): Option[Boolean] =
      withoutCasts(cond) match
        case c: Call =>
            c.name match
              case Operators.logicalNot =>
                  c.argumentOption(1).collect { case e: Expression => e }.flatMap(valueAtZero(
                    _,
                    key
                  ))
                      .map(!_)
              case Operators.logicalAnd =>
                  val l =
                      c.argumentOption(1).collect { case e: Expression => e }.flatMap(valueAtZero(
                        _,
                        key
                      ))
                  val r =
                      c.argumentOption(2).collect { case e: Expression => e }.flatMap(valueAtZero(
                        _,
                        key
                      ))
                  if l.contains(false) || r.contains(false) then Some(false)
                  else if l.contains(true) && r.contains(true) then Some(true)
                  else None
              case Operators.logicalOr =>
                  val l =
                      c.argumentOption(1).collect { case e: Expression => e }.flatMap(valueAtZero(
                        _,
                        key
                      ))
                  val r =
                      c.argumentOption(2).collect { case e: Expression => e }.flatMap(valueAtZero(
                        _,
                        key
                      ))
                  if l.contains(true) || r.contains(true) then Some(true)
                  else if l.contains(false) && r.contains(false) then Some(false)
                  else None
              case op if Comparisons.contains(op) =>
                  for
                    l <- c.argumentOption(1).collect { case e: Expression => e }
                    r <- c.argumentOption(2).collect { case e: Expression => e }
                    (lv, rv) <-
                        if isKey(l, key) then literalNumber(r).map(v => (BigDecimal(0), v))
                        else if isKey(r, key) then literalNumber(l).map(v => (v, BigDecimal(0)))
                        else None
                  yield compare(op, lv, rv)
              case _ if isKey(c, key) => Some(false)
              case _                  => None
        case e if isKey(e, key) => Some(false)
        case _                  => None

  private val Comparisons = Set(
    Operators.equals,
    Operators.notEquals,
    Operators.lessThan,
    Operators.lessEqualsThan,
    Operators.greaterThan,
    Operators.greaterEqualsThan
  )

  private def compare(op: String, l: BigDecimal, r: BigDecimal): Boolean = op match
    case Operators.equals            => l == r
    case Operators.notEquals         => l != r
    case Operators.lessThan          => l < r
    case Operators.lessEqualsThan    => l <= r
    case Operators.greaterThan       => l > r
    case Operators.greaterEqualsThan => l >= r
    case _                           => false

  /** The expression is the variable `key` names, or a magnitude of it that is zero exactly when it
    * is (`fabs(x)`, `abs(x)`): a comparison of either against a number says the same about zero.
    */
  private def isKey(e: Expression, key: String): Boolean =
      withoutCasts(e) match
        case c: Call if MagnitudeFunctions.contains(c.name) =>
            c.argumentOption(1).collect { case x: Expression => x }.exists(isKey(_, key))
        case other => OverlayFacts.variableKey(other).contains(key)

  private val MagnitudeFunctions =
      Set("fabs", "fabsf", "fabsl", "abs", "labs", "llabs", "__builtin_fabs", "__builtin_fabsf")

  // ---- shifts -------------------------------------------------------------------------------

  def undefinedShift(
    atom: Cpg,
    range: Expression => Option[(BigInt, BigInt)],
    record: (StoredNode, String) => Unit
  ): Unit =
      atom.call.filter(c => ShiftOps.contains(c.name)).foreach { shift =>
          for
            operand <- shift.argumentOption(1).collect { case e: Expression => e }
            amount  <- shift.argumentOption(2).collect { case e: Expression => e }
            width   <- promotedWidth(operand)
          do
            val known    = definitionValues(amount).filter(_.nonEmpty)
            val definite = known.exists(vs => vs.exists(v => v < 0 || v >= width))
            // C11 6.5.7p4: a negative signed value shifted left is undefined, whatever the
            // amount; C++20 defines it (two's complement), so the check is C's
            val negativeOperand = shift.name == Operators.shiftLeft && isC(shift) &&
                isSignedType(operand) &&
                definitionValues(operand).exists(vs => vs.nonEmpty && vs.forall(_ < 0))
            val unbounded = known.isEmpty && isUntrusted(amount) &&
                !shiftAmountBounded(amount, shift, width, range)
            if definite || negativeOperand || unbounded then record(shift, RuleUndefinedShift)
      }

  private def isC(c: Call): Boolean =
    val file = c.method.filename.toLowerCase
    file.endsWith(".c") || file.endsWith(".h")

  /** The amount lies in [0, width): by construction (`k & 31`, `k % 32`), by dominating guards on
    * both sides (an unsigned amount is bounded below by its type), or by an enclosing short-circuit
    * operand's condition.
    */
  private def shiftAmountBounded(
    amount: Expression,
    use: Call,
    width: Int,
    range: Expression => Option[(BigInt, BigInt)]
  ): Boolean =
    if range(amount).exists { case (lo, hi) => lo >= 0 && hi < width } then return true
    // an amount the program reduces into the width itself: `x % k` or `x & m` (k, m + 1 no more
    // than the width), directly or as the amount variable's every definition
    def reduced(e: Expression): Boolean = withoutCasts(e) match
      case c: Call if c.name == Operators.modulo =>
          c.argumentOption(2).collect { case k: Expression => k }.flatMap(literalNumber).exists(k =>
              k > 0 && k <= width
          )
      case c: Call if c.name == Operators.and =>
          c.argument.l.collect { case k: Expression => k }.flatMap(literalNumber).exists(m =>
              m >= 0 && m < width
          )
      case i: Identifier =>
          definitionAssignments(i).exists(as =>
              as.nonEmpty && as.forall(
                _.argumentOption(2).collect { case r: Expression => r }.exists(r =>
                    withoutCasts(r) match
                      case rc: Call => reduced(rc)
                      case _        => false
                )
              )
          )
      case _ => false
    if reduced(amount) then return true
    val key = OverlayFacts.variableKey(withoutCasts(amount))
    key.exists { k =>
      var above = false
      var below = isUnsignedType(amount)
      def take(cmp: Call, holds: Boolean): Unit =
          GuardPass.directionalFacts(cmp, holds).foreach { case (bounded, isAbove, bound) =>
              if isKey(bounded, k) then
                literalNumber(bound).foreach { v =>
                  val strict = GuardPass.isStrict(cmp, holds)
                  if isAbove then
                    if (strict && v <= width) || (!strict && v < width) then above = true
                  else if (strict && v >= -1) || (!strict && v >= 0) then below = true
                }
          }
      GuardPass.guardingControllers(use).foreach { controller =>
          GuardPass.conjunctsAt(controller, use).foreach { case (cmp, holds) => take(cmp, holds) }
      }
      var child: StoredNode          = use
      var cursor: Option[StoredNode] = use._astIn.nextOption()
      while cursor.isDefined do
        cursor.get match
          case c: Call =>
              val holds: Option[Boolean] = c.name match
                case Operators.logicalAnd if c.argumentOption(2).exists(_.id == child.id) =>
                    Some(true)
                case Operators.logicalOr if c.argumentOption(2).exists(_.id == child.id) =>
                    Some(false)
                case Operators.conditional if c.argumentOption(2).exists(_.id == child.id) =>
                    Some(true)
                case Operators.conditional if c.argumentOption(3).exists(_.id == child.id) =>
                    Some(false)
                case _ => None
              holds.foreach { h =>
                  c.argumentOption(1).collect { case cond: Call => cond }.foreach { cond =>
                      GuardPass.conjuncts(cond, h).getOrElse(Nil).foreach { case (cmp, ch) =>
                          take(cmp, ch)
                      }
                  }
              }
              child = c
              cursor = c._astIn.nextOption()
          case _ => cursor = None
      end while
      above && below
    }
  end shiftAmountBounded

  /** The width, in bits, of the shift's left operand after the integer promotions: anything
    * narrower than `int` is an `int`. None when the type is not one whose width every target this
    * analysis supports agrees on (`long` is 32 bits on LLP64 and 64 on LP64).
    */
  private def promotedWidth(operand: Expression): Option[Int] =
    val t          = typeOf(operand)
    val qualifiers = Set("const", "volatile", "signed", "unsigned")
    val bare       = t.split("\\s+").filterNot(qualifiers.contains).mkString(" ").trim
    bare match
      case "char" | "short" | "short int" | "int" | "" | "_Bool" | "bool" | "uint8_t" | "int8_t" |
          "uint16_t" | "int16_t" | "uint32_t" | "int32_t" | "u_char" | "u_short" | "u_int" =>
          if t.isEmpty || t == "ANY" then None else Some(32)
      case "long long" | "long long int" | "uint64_t" | "int64_t" | "u_int64_t" => Some(64)
      case _                                                                    => None

  /** The type an operand has as written: a cast's is its target type, whatever it converts. */
  private def typeOf(e: Expression): String =
      Option(e.property("TYPE_FULL_NAME")).map(_.toString.trim).getOrElse("")

  private def isSignedType(e: Expression): Boolean =
    val t = typeOf(e)
    t.nonEmpty && t != "ANY" && !t.contains("unsigned") && !t.startsWith("uint") &&
    !t.startsWith("u_") && !t.contains("size_t")

  private def isUnsignedType(e: Expression): Boolean =
    val t = typeOf(e)
    t.contains("unsigned") || t.startsWith("uint") || t.startsWith("u_") || t == "size_t"

  // ---- pointer subtraction ------------------------------------------------------------------

  def crossObjectPointerDifference(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.call.nameExact(Operators.subtraction).foreach { sub =>
          for
            l <- sub.argumentOption(1).collect { case e: Expression => e }
            r <- sub.argumentOption(2).collect { case e: Expression => e }
            if isPointerValued(l) && isPointerValued(r)
            lb <- objectOf(l)
            rb <- objectOf(r)
            if lb.distinct && rb.distinct && lb.id != rb.id
          do record(sub, RulePointerDifference)
      }

  /** A pointer operand: its type is a pointer or an array (a decayed array is a pointer to its
    * first element).
    */
  private def isPointerValued(e: Expression): Boolean =
    val t = typeOf(e)
    t.endsWith("*") || t.contains("[")

  /** The object an expression points into, and whether it is one whose identity is known: a local
    * or global array, an allocation, a local's address. A parameter's pointee is the caller's - two
    * parameters can point into one object, so a parameter is an object only for the overlap rule,
    * which asks whether two operands are the SAME object.
    */
  private final case class PointedObject(id: Long, distinct: Boolean)

  private def objectOf(e: Expression, depth: Int = 0): Option[PointedObject] =
    if depth > 4 then return None
    withoutCasts(e) match
      case i: Identifier =>
          declarationOf(i) match
            case Some(l: Local) if isArrayDeclaration(l.typeFullName) =>
                Some(PointedObject(l.id(), distinct = true))
            case Some(p: MethodParameterIn) =>
                Some(PointedObject(p.id(), distinct = false))
            case Some(m: Member) if isArrayDeclaration(m.typeFullName) =>
                Some(PointedObject(m.id(), distinct = true))
            case Some(_: Local) =>
                // a pointer local: the object its every assignment points into
                definitionAssignments(i).filter(_.nonEmpty).flatMap { assigns =>
                  val objects = assigns.map(a =>
                      a.argumentOption(2).collect { case x: Expression => x }
                          .flatMap(objectOf(_, depth + 1))
                  )
                  Option.when(objects.forall(_.isDefined) &&
                      objects.flatten.map(_.id).distinct.size == 1)(objects.head).flatten
                }
            case _ => None
      case c: Call =>
          c.name match
            case Operators.addition | Operators.subtraction =>
                c.argument.l.collect { case x: Expression => x }.find(isPointerValued)
                    .flatMap(objectOf(_, depth + 1))
            case Operators.addressOf =>
                c.argumentOption(1).collect { case x: Expression => x }.flatMap(addressedObject(
                  _,
                  depth + 1
                ))
            case n if HaystackApis.contains(n) =>
                c.argumentOption(1).collect { case x: Expression => x }.flatMap(objectOf(
                  _,
                  depth + 1
                ))
            case _ if c.tag.name(MemoryApiPass.TagAlloc).nonEmpty =>
                Some(PointedObject(c.id(), distinct = true))
            case _ => None
      case _ => None
    end match
  end objectOf

  /** The object `&x`, `&x[i]`, `&x.f` and `&x->f` point into: x's own for a local array, a local
    * scalar or a struct local; the pointee's for `&p[i]` and `&p->f`.
    */
  private def addressedObject(e: Expression, depth: Int = 0): Option[PointedObject] =
      if depth > 4 then None
      else
        withoutCasts(e) match
          case i: Identifier =>
              declarationOf(i).collect { case l: Local => PointedObject(l.id(), distinct = true) }
          case c: Call
              if c.name == Operators.indexAccess || c.name == Operators.fieldAccess =>
              c.argumentOption(1).collect { case x: Expression => x }
                  .flatMap(addressedObject(_, depth + 1))
          case c: Call
              if c.name == Operators.indirectIndexAccess || c.name == Operators.indirectFieldAccess =>
              c.argumentOption(1).collect { case x: Expression => x }.flatMap(objectOf(
                _,
                depth + 1
              ))
          case _ => None

  private def isArrayDeclaration(t: String): Boolean = t.trim.endsWith("]")

  private def declarationOf(i: Identifier): Option[AstNode] =
      i.refsTo.collectFirst {
          case l: Local             => l
          case p: MethodParameterIn => p
      }.orElse(i.method.local.nameExact(i.name).headOption)
          .orElse(i.method.parameter.nameExact(i.name).headOption)

  // ---- overlapping copies -------------------------------------------------------------------

  def overlappingCopy(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.call.foreach { call =>
        val args = call.argument.l.collect { case e: Expression => e }
        def withRole(role: String): Option[(Expression, String)] =
            args.iterator.flatMap(a => a.tag.nameExact(role).value.headOption.map(a -> _))
                .nextOption()
        // the API the inventory tagged the call as - a `_chk` or `__builtin_` spelling carries
        // the API it stands for
        val dstRole = withRole(MemoryApiPass.TagDst)
        val api     = dstRole.map(_._2).getOrElse("")
        if NoOverlapApis.contains(api) then
          val dst = dstRole.map(_._1)
          val src = withRole(MemoryApiPass.TagSrc).map(_._1)
          val len = withRole(MemoryApiPass.TagLen).map(_._1)
          for
            d               <- dst
            s               <- src
            (dObj, dOffset) <- objectAndOffset(d)
            (sObj, sOffset) <- objectAndOffset(s)
            if dObj == sObj
          do
            val length = len.flatMap(literalNumber).map(_.toBigInt)
            val overlaps = (dOffset, sOffset) match
              case (Some(a), Some(b)) =>
                  length match
                    case Some(n) => n > 0 && (a - b).abs < n
                    // a string copy runs to the source's terminator, whatever its length: one
                    // object at two known offsets is the overlap the library forbids
                    case None => !api.startsWith("mem") || a == b
              case _ => false
            if overlaps then record(call, RuleOverlappingCopy)
        end if
      }

  /** The object an argument points into and its constant offset in elements: `buf + 6`, `out - 16`,
    * `&buf[4]`, `buf`. Offsets add up through nested arithmetic (`ctrl + capacity + 1`); one
    * non-constant step makes the whole offset unknown (None), which the overlap test cannot decide.
    */
  private def objectAndOffset(e: Expression, depth: Int = 0): Option[(Long, Option[BigInt])] =
      withoutCasts(e) match
        case c: Call
            if depth < 8 && (c.name == Operators.addition || c.name == Operators.subtraction) =>
            val parts = c.argument.l.collect { case x: Expression => x }
            val sign  = if c.name == Operators.subtraction then -1 else 1
            for
              base <- parts.find(isPointerValued)
              // `p - k` moves p; `p - q` is a distance, and `k - p` is not a pointer
              if c.name == Operators.addition ||
                  parts.headOption.exists(_.id == base.id) && !parts.drop(1).exists(isPointerValued)
              (obj, baseOffset) <- objectAndOffset(base, depth + 1)
            yield
              val step = parts.filterNot(_.id == base.id).headOption
                  .flatMap(literalNumber).map(_.toBigInt * sign)
              (obj, for a <- baseOffset; b <- step yield a + b)
        case c: Call if c.name == Operators.addressOf =>
            c.argumentOption(1).collect { case x: Expression => x }.flatMap {
                case ix: Call
                    if ix.name == Operators.indexAccess || ix.name == Operators.indirectIndexAccess =>
                    for
                      base <- ix.argumentOption(1).collect { case x: Expression => x }
                      obj  <- objectOf(base)
                    yield (
                      obj.id,
                      ix.argumentOption(2).collect { case x: Expression => x }.flatMap(
                        literalNumber
                      )
                          .map(_.toBigInt)
                    )
                case other => addressedObject(other).map(o => (o.id, Some(BigInt(0))))
            }
        case other => objectOf(other).map(o => (o.id, Some(BigInt(0))))

  // ---- shared -------------------------------------------------------------------------------

  /** The values every definition of a variable states, when each is a number: Some(empty) for no
    * numeric knowledge at all is not returned - None is. A literal operand is its own one value.
    */
  private def definitionValues(e: Expression): Option[List[BigDecimal]] =
      withoutCasts(e) match
        case lit: Literal => literalNumber(lit).map(List(_))
        case i: Identifier =>
            definitionAssignments(i).filter(_.nonEmpty).flatMap { assigns =>
              val values = assigns.map(a =>
                  a.argumentOption(2).collect { case x: Expression => x }.flatMap(literalNumber)
              )
              Option.when(values.forall(_.isDefined))(values.flatten)
            }
        case other => literalNumber(other).map(List(_))

  /** Is the value read from an untrusted source on some path - the inventory's reads, and what is
    * computed from them? A parameter read as it is takes its callers' arguments: it is untrusted
    * when a call the graph resolves passes it an untrusted value. A parameter alone is the caller's
    * contract.
    */
  private def isUntrusted(e: Expression): Boolean =
      withoutCasts(e) match
        // an element's value is the array's content: the index only says which one. A table
        // nothing in the method writes and no parameter names (a file's constant, unresolved
        // by the frontend) has no content of the method's making - the walk back from it only
        // wanders into its index's definitions
        case c: Call
            if c.name == Operators.indexAccess || c.name == Operators.indirectIndexAccess =>
            c.argumentOption(1).collect { case b: Expression => b }.exists {
                case b: Identifier =>
                    (ownDefinitions(b).nonEmpty || parameterOf(b).isDefined) && isUntrustedValue(b)
                case other => isUntrustedValue(other)
            }
        case other => isUntrustedValue(other)

  private def isUntrustedValue(e: Expression): Boolean =
      ValueOriginPass.originNamesOf(e).contains(ValueOriginPass.OriginUntrustedRead) ||
          parameterOf(e).exists { p =>
              p.method.callIn.l.exists { site =>
                  site.argumentOption(p.index).collect { case a: Expression => a }.exists(a =>
                      ValueOriginPass.originNamesOf(a).contains(ValueOriginPass.OriginUntrustedRead)
                  )
              }
          }

  /** The parameter an operand reads with no definition of its own in between. */
  private def parameterOf(e: Expression): Option[MethodParameterIn] =
      withoutCasts(e) match
        case i: Identifier if ownDefinitions(i).isEmpty =>
            declarationOf(i).collect { case p: MethodParameterIn => p }
        case _ => None

  /** The definitions of the variable an identifier reads that reach it: the reaching-definition
    * walk is transitive, so only the ones that write that name are its own.
    */
  private def ownDefinitions(i: Identifier): List[Identifier] =
      OverlayFacts.reachingDefsIn(i).collect { case d: Identifier if d.name == i.name => d }.distinct

  /** The plain assignments that define the variable an identifier reads, when those are its only
    * writes: None when another write reaches it (an increment, a compound assignment, its address
    * handed out), whose value this reader does not follow. The walk also returns the variable's
    * reads as call arguments, which write nothing.
    */
  private def definitionAssignments(i: Identifier): Option[List[Call]] =
    val writes = ownDefinitions(i).map { d =>
        d._astIn.collectFirst { case p: Call => p } match
          case Some(p)
              if p.name == Operators.assignment && p.argumentOption(1).exists(_.id == d.id) =>
              Some(Some(p))
          case Some(p) if WriteOps.contains(p.name) && p.argumentOption(1).exists(_.id == d.id) =>
              None
          case _ => Some(None)
    }
    Option.when(writes.forall(_.isDefined))(writes.flatten.flatten)

  private val WriteOps = Set(
    Operators.addressOf,
    Operators.preIncrement,
    Operators.preDecrement,
    Operators.postIncrement,
    Operators.postDecrement,
    Operators.assignmentPlus,
    Operators.assignmentMinus,
    Operators.assignmentMultiplication,
    Operators.assignmentDivision,
    Operators.assignmentModulo,
    Operators.assignmentShiftLeft,
    Operators.assignmentArithmeticShiftRight,
    Operators.assignmentLogicalShiftRight,
    Operators.assignmentAnd,
    Operators.assignmentOr,
    Operators.assignmentXor
  )

  private def assignmentOf(d: Identifier): Option[Call] =
      d._astIn.collectFirst {
          case a: Call
              if a.name == Operators.assignment && a.argumentOption(1).exists(_.id == d.id) =>
              a
      }

  /** A number an expression states: an integer the frontend evaluated, or a floating literal. */
  private def literalNumber(e: Expression): Option[BigDecimal] =
      withoutCasts(e) match
        case c: Call if c.name == Operators.minus =>
            c.argumentOption(1).collect { case x: Expression => x }.flatMap(literalNumber).map(-_)
        case other =>
            IndexRange.literal(other).map(BigDecimal(_)).orElse(other match
              case lit: Literal =>
                  val code = lit.code.trim.toLowerCase.stripSuffix("f").stripSuffix("l")
                  scala.util.Try(BigDecimal(code)).toOption
              case _ => None
            )

  private def withoutCasts(e: Expression): Expression = e match
    case c: Call if c.name == Operators.cast =>
        c.argument.l.collect { case x: Expression => x }.lastOption.map(withoutCasts).getOrElse(e)
    case other => other
end UndefinedOperationRules
