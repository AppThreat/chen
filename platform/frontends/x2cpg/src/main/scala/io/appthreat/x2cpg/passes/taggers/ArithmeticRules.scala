package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** Arithmetic on values the program READS - the operations a bounded model checker asserts at every
  * use (`--signed-overflow-check`, `--conversion-check`) asked only where the operand's value is
  * known or comes from input. A value that merely might be large (a caller's parameter, a struct
  * field) is the caller's contract, not a defect.
  *
  *   - MS-INT-003 (CWE-190): `+`, `-`, `*`, `++` and `--` whose result can leave the type it is
  *     kept in. **Definite**: every definition of each operand is a constant and the exact result
  *     does not fit - `data = INT_MAX; data + 1`, `CHAR_MIN - 1`, the `max`/`min`/`large` sources.
  *     **Input**: an operand an input read gives (`fscanf` into it, `atoi` of a `fgets` buffer),
  *     with no guard bounding the side that wraps and no clamp.
  *   - MS-CONV-001 (CWE-197): a narrowing cast of a value that can exceed the target - `(char)
  *     data` of an input `int`, or of a constant that does not fit. Bounded by a guard against a
  *     constant the target holds, or clamped, it stands down.
  *   - MS-CONV-002 (CWE-194): a possibly-negative SIGNED input value converted to an unsigned size
  *     \- an allocation size, a copy length, `strncpy`'s count. The sign conversion is the defect:
  *     `malloc(data)` with a negative `data` asks for a near-SIZE_MAX allocation.
  *
  * The DEFINITE arms (constants, negative constants, allocation sizes) report above their rules'
  * default; the INPUT arms report at `low`: an input read reaching an operand with no guard this
  * reader sees is strong evidence, but the guard languages it must parse (a failing disjunction
  * after an early exit, a loop's break side) are richer than the dominating-guard question it asks
  * today, and where those guards protect real code the arm would lie.
  *
  * Widths and signedness come from the frontends' type facts ([[OverlayFacts.integralWidth]] over
  * `typeFullName`), never from a literal's spelling. The guard questions reuse GuardPass's
  * comparison semantics at operand level, as MS-INT-001 does. Each rule returns the (node, rule)
  * pairs whose arm is definite - the renderer promotes those above the rule's default confidence.
  */
object ArithmeticRules:

  import MemorySafetyFindingPass.*
  import OverlayFacts.*

  private val ArithOps = Set(
    "<operator>.addition",
    "<operator>.subtraction",
    "<operator>.multiplication",
    // the unary minus: -INT_MIN leaves the type, the same arithmetic one operand shorter
    "<operator>.minus"
  )

  /** The comparison and logical operators: their result is a boolean whatever the operands read. */
  private val BooleanOps = Set(
    "<operator>.equals",
    "<operator>.notEquals",
    "<operator>.lessThan",
    "<operator>.lessEqualsThan",
    "<operator>.greaterThan",
    "<operator>.greaterEqualsThan",
    "<operator>.logicalAnd",
    "<operator>.logicalOr",
    "<operator>.logicalNot"
  )

  private val IncrementOps = Set(
    "<operator>.postIncrement",
    "<operator>.preIncrement",
    "<operator>.postDecrement",
    "<operator>.preDecrement"
  )

  private val InputOrigins = Set(ValueOriginPass.OriginUntrustedRead)

  /** The constant every definition of `i` agrees on, through casts; None when any definition is not
    * a constant. reachingDefsIn is transitive, so only the definitions that write `i` itself count.
    */
  private def constantDefOf(i: Identifier): Option[BigInt] =
    // a variable whose ADDRESS a call receives is not a constant even when the def walk sees
    // only the initialiser: an input call writes through it (`fscanf(f, "%d", &n)`), and a
    // library call may - the OSSL_PARAM idiom smuggles `&len` inside a struct the callee
    // fills (`size_t len = UINT_MAX; construct_size_t(.., &len); get_params(ctx, params);
    // (int)len`). The write is invisible to reaching definitions in this frontend, and
    // reading the initialiser alone would call the value what it said before the call
    // replaced it
    if addressTakenByCall(i) then return None
    // only defs that PRECEDE the use in program order: a def later in the method reaches an
    // earlier use only across a loop back-edge (`blen = 0` at the loop's end reaches `--blen`
    // at its head), and on that path the variable's ENTRY value - whatever the parameter or
    // initialiser gave it - flows too, which no assignment def names
    val useLine = i.lineNumber.map(_.intValue).getOrElse(Int.MinValue)
    val defs = reachingDefsIn(i)
        .collect { case d: Identifier if d.name == i.name => d }
        .filter(d => d.lineNumber.map(_.intValue).getOrElse(Int.MaxValue) <= useLine)
        .flatMap(_._astIn.collectFirst {
            case a: Call if a.name == "<operator>.assignment" => a
        })
    val rhss = defs.flatMap(a => a.argumentOption(2).toList)
    val lits = rhss.flatMap(x => IndexRange.literal(withoutCasts(x)))
    // EVERY definition must be a literal, and they must agree: one non-literal definition
    // (`data = source(data)`) leaves the value whatever the callee returned, and reading
    // the literals that remain would call -1 what the source actually caps
    Option.when(defs.nonEmpty && lits.size == rhss.size)(
      lits.distinct match
        case List(v) => Some(v)
        case _       => None
    ).flatten
  end constantDefOf

  private def withoutCasts(e: Expression): Expression = e match
    case c: Call if c.name == "<operator>.cast" =>
        c.argumentOption(2).orElse(c.argumentOption(1)).map(withoutCasts).getOrElse(c)
    case other => other

  private def operandsOf(c: Call): List[Expression] =
      c.argument.l.collect { case e: Expression => e }.toList

  /** The constant an operand states: its own literal, or the one constant every definition of the
    * variable agrees on.
    */
  private def constantOf(op: Expression): Option[BigInt] = withoutCasts(op) match
    case i: Identifier => constantDefOf(i).orElse(IndexRange.literal(i))
    case other         => IndexRange.literal(other)

  /** The operand's value is the length of a string that already exists (`strlen`, `strnlen`, a size
    * a reader reported): bounded by that string's own content, like the allocation rule's
    * strlen-derived exemption - `100 - strlen(s)` is the remainder idiom, not a wrap.
    */
  private def lengthDerived(op: Expression): Boolean =
      withoutCasts(op) match
        case c: Call => c.name == "strlen" || c.name == "strnlen" || c.name == "wcslen" ||
            c.name == "strnlen_s"
        case i: Identifier =>
            OverlayFacts
                .reachingDefsIn(i)
                .collect { case d: Identifier if d.name == i.name => d }
                .flatMap(_._astIn.collectFirst {
                    case a: Call if a.name == "<operator>.assignment" => a
                })
                .flatMap(_.argumentOption(2).toList)
                .exists(x =>
                    withoutCasts(x) match
                      case c: Call => c.name == "strlen" || c.name == "strnlen" ||
                          c.name == "wcslen"
                      case _ => false
                )
        case _ => false

  /** Any call receives the variable's address, directly or nested in an argument (`&n` as an
    * argument, or inside a struct initialiser an argument builds): from that call on the value is
    * whatever the callee left there.
    */
  private def addressTakenByCall(i: Identifier): Boolean =
    val useLine = i.lineNumber.map(_.intValue).getOrElse(-1)
    i.method.ast.isCall.l.exists { c =>
        !c.name.startsWith("<operator>") &&
        c.lineNumber.map(_.intValue).getOrElse(Int.MaxValue) <= useLine &&
        c.argument.l.exists {
            case a: Call if a.name == "<operator>.addressOf" =>
                a.argument.l.collect { case x: Identifier => x.name }.contains(i.name)
            case _ => false
        }
    }

  /** An input call writes the variable through its address (`fscanf(f, "%d", &n)`, the
    * `untrustedCall` family with no single buffer argument to tag): from that call on, the variable
    * holds what the input gave.
    */
  private def writtenThroughAddressByInput(i: Identifier): Boolean =
    val useLine = i.lineNumber.map(_.intValue).getOrElse(-1)
    i.method.ast.isCall.l.exists { c =>
        !c.name.startsWith("<operator>") &&
        c.tag.name(MemoryApiPass.TagUntrustedRead).nonEmpty &&
        c.lineNumber.map(_.intValue).getOrElse(Int.MaxValue) <= useLine &&
        c.argument.l.exists {
            case a: Call if a.name == "<operator>.addressOf" =>
                a.argument.l.collect { case x: Identifier => x.name }.contains(i.name)
            case _ => false
        }
    }

  /** The standard clamp guards the variable on both sides by redefining it: `if (x < lo) x = lo; if
    * (x > hi) x = hi;`. Both stores under both comparisons are the author's own answer to the wrap
    * question.
    */
  private def clampedByRedefinition(i: Identifier): Boolean =
    val stores = i.method.ast.isCall.nameExact("<operator>.assignment").l.filter(a =>
        a.argumentOption(1).exists {
            case t: Identifier => t.name == i.name
            case _             => false
        } && a.argumentOption(2).exists(x => IndexRange.literal(withoutCasts(x)).isDefined)
    )
    def guardedFromBelow(a: Call): Boolean =
        GuardPass.guardingControllers(a).exists(cond =>
            GuardPass.conjuncts(cond, holds = true).getOrElse(Nil).exists {
                case (cmp, _) =>
                    (cmp.name == "<operator>.lessThan" || cmp.name == "<operator>.lessEqualsThan") &&
                    cmp.argument.l.collect { case x: Identifier => x.name }.contains(i.name)
            }
        )
    def guardedFromAbove(a: Call): Boolean =
        GuardPass.guardingControllers(a).exists(cond =>
            GuardPass.conjuncts(cond, holds = true).getOrElse(Nil).exists {
                case (cmp, _) =>
                    (cmp.name == "<operator>.greaterThan" ||
                        cmp.name == "<operator>.greaterEqualsThan") &&
                    cmp.argument.l.collect { case x: Identifier => x.name }.contains(i.name)
            }
        )
    stores.exists(guardedFromBelow) && stores.exists(guardedFromAbove)
  end clampedByRedefinition

  /** Does an input read reach this operand - directly, or through the variable's definitions
    * (`fscanf(fd, "%d", &n)` then `n + 1`, `atoi` of a `fgets` buffer)? The origin walk the rest of
    * the overlay uses, asked of the operand itself.
    */
  private def inputFed(op: Expression): Boolean =
      ValueOriginPass.originNamesOf(op).exists(InputOrigins.contains) || (withoutCasts(op) match
        case i: Identifier =>
            reachingDefsIn(i)
                .collect { case d: Identifier if d.name == i.name => d }
                .exists(d =>
                    ValueOriginPass.originNamesOf(d).exists(InputOrigins.contains) ||
                        d.tag.name(MemoryApiPass.TagUntrustedRead).nonEmpty
                ) || writtenThroughAddressByInput(i)
        case _ => false
      )

  /** The value ranges the definitions of a local give (a mask, a constant, a bounded sum). No enum
    * facts and no caller facts: the question here is the operand's own value.
    */
  private val valueRanges = new java.util.WeakHashMap[AnyRef, IndexRange]()

  /** The range is only as good as the definitions it reads: a variable whose address is taken (an
    * `fscanf(&n)` fills it) has a definition the walk does not see, and `n = 0` before it would
    * read as the whole answer.
    */
  private def rangesOf(graph: AnyRef, e: Expression): Option[IndexRange.Range] =
    val addressTaken = e.ast.isIdentifier.l.exists { i =>
        i.method.ast.isCall.nameExact("<operator>.addressOf").l.exists(a =>
            a.argumentOption(1).exists {
                case x: Identifier => x.name == i.name
                case _             => false
            }
        )
    }
    if addressTaken then None else rangesOfUnchecked(graph, e)

  private def rangesOfUnchecked(graph: AnyRef, e: Expression): Option[IndexRange.Range] =
    val ir = valueRanges.synchronized {
        Option(valueRanges.get(graph)).getOrElse {
            val made = IndexRange(
              {
                  case i: Identifier => i.typeFullName
                  case c: Call       => c.typeFullName
                  case l: Literal    => l.typeFullName
                  case _             => ""
              },
              _ => false,
              _ => None
            )
            valueRanges.put(graph, made)
            made
        }
    }
    ir.of(e)

  private val NoReturnCalls = Set("exit", "abort", "_exit", "_Exit", "quick_exit", "longjmp")

  /** The innermost loop whose body holds the node. */
  private def enclosingLoopBodyOf(n: CfgNode): Option[ControlStructure] =
    var cursor: Option[io.shiftleft.codepropertygraph.generated.nodes.StoredNode] =
        n._astIn.nextOption()
    var found: Option[ControlStructure] = None
    while found.isEmpty && cursor.isDefined do
      cursor.get match
        case cs: ControlStructure
            if Set("FOR", "WHILE", "DO").contains(cs.controlStructureType) =>
            found = Some(cs)
        case other => cursor = other._astIn.nextOption()
    found

  /** The statement a `break` leaves: the innermost loop or switch around it. */
  private def breakTargetOf(n: CfgNode): Option[ControlStructure] =
    var cursor: Option[io.shiftleft.codepropertygraph.generated.nodes.StoredNode] =
        n._astIn.nextOption()
    var found: Option[ControlStructure] = None
    while found.isEmpty && cursor.isDefined do
      cursor.get match
        case cs: ControlStructure
            if Set("FOR", "WHILE", "DO", "SWITCH").contains(cs.controlStructureType) =>
            found = Some(cs)
        case other => cursor = other._astIn.nextOption()
    found

  /** A dominating guard bounds the key's variable on the side `above`: the author's own claim,
    * valued or not.
    */
  private def guardBounds(site: CfgNode, key: String, above: Boolean): Boolean =
      GuardPass.guardingControllers(GuardPass.statementRootOf(site)).exists { cond =>
          GuardPass
              .conjuncts(cond, holds = true)
              .getOrElse(Nil)
              .flatMap { case (cmp, h) => GuardPass.directionalFacts(cmp, h) }
              .exists { case (bounded, isAbove, _) =>
                  isAbove == above && variableKey(bounded).contains(key)
              }
      } || {
          // an EARLY-EXIT guard bounds the statement that follows it at its NOT-holding
          // polarity: `if (x < 0 || x > 100) return; use x` runs the use where both sides
          // failed, and a failing disjunction makes every disjunct fail
          // the way out of the if-branch: a return, a goto, a call that does not return, or - when
          // the site sits in the same loop body - a break or continue (the loop's own side of
          // the guard: `for (...) { if (n > MAX) break; use(n); }`)
          val siteLoop = enclosingLoopBodyOf(site)
          def exitsEarly(cs: ControlStructure): Boolean =
            // the branch taken when the condition holds: the child after the condition, a block
            // or a single unbraced statement (`if (bad) exit(1);`)
            val condIds = cs.condition.l.map(_.id()).toSet
            cs.astChildren.l.filterNot(n => condIds.contains(n.id()))
                .sortBy(_.order.intValue)
                .headOption
                .exists { thenBranch =>
                    thenBranch.ast.isReturn.l.nonEmpty ||
                    thenBranch.ast.isCall.l.exists(c => NoReturnCalls.contains(c.name)) ||
                    thenBranch.ast.isControlStructure.l.exists(j =>
                        j.controlStructureType == "GOTO"
                    ) ||
                    // the jump must leave the site's own loop: a break inside an inner loop or a
                    // switch in the branch exits only that
                    thenBranch.ast.isControlStructure.l.exists(j =>
                        (j.controlStructureType == "BREAK" &&
                            siteLoop.exists(l => breakTargetOf(j).exists(_.id() == l.id()))) ||
                            (j.controlStructureType == "CONTINUE" &&
                                siteLoop.exists(l =>
                                    enclosingLoopBodyOf(j).exists(_.id() == l.id())
                                ))
                    )
                }
          end exitsEarly
          val siteLine = site.lineNumber.map(_.intValue).getOrElse(-1)
          site.method.ast.collectAll[ControlStructure].l.exists { cs =>
              cs.controlStructureType == "IF" &&
              // the guard protects what FOLLOWS it: a site inside the branch that exits is on the
              // path where the condition held
              !cs.ast.exists(_.id() == site.id()) &&
              cs.condition.exists(cond =>
                  cond.lineNumber.map(_.intValue).getOrElse(Int.MaxValue) < siteLine &&
                      exitsEarly(cs)
              ) &&
              cs.condition.toList
                  .collect { case c: Call => c }
                  .flatMap(c => GuardPass.conjuncts(c, holds = false).getOrElse(Nil))
                  .flatMap { case (cmp, h) => GuardPass.directionalFacts(cmp, h) }
                  .exists { case (bounded, isAbove, _) =>
                      isAbove == above && variableKey(bounded).contains(key)
                  }
          }
      }

  /** The operand is capped ABOVE before the site: the question an allocation's size asks (a lower
    * bound, `data > strlen(s)`, leaves every large value through). A guard on the other side, or
    * the operand's own lower-bound tag, does not count.
    */
  private[taggers] def operandBoundedAbove(site: Call, opnd: Expression): Boolean =
      variableKey(opnd).exists(k => guardBounds(site, k, above = true)) ||
          opnd.tag.name(GuardPass.TagAbove).nonEmpty ||
          opnd.tag.name(MemoryApiPass.TagClamp).nonEmpty || (withoutCasts(opnd) match
            case i: Identifier => clampedByRedefinition(i)
            case _             => false
          )

  /** Nothing the program does lets the operand leave its type here: a guard the author wrote around
    * the operation (either side), a clamp in the expression, the operand's own tag - or, for a
    * parameter, a bound EVERY caller's argument carries at its call site (the good 41 sources cap
    * the value before handing it to the shared sink; the cap is a fact of the caller, and the
    * callee's own body sees none of it).
    */
  private[taggers] def operandKeptInType(site: Call, opnd: Expression): Boolean =
    val key = variableKey(opnd)
    val guarded = key.exists(k =>
        guardBounds(site, k, above = true) || guardBounds(site, k, above = false)
    ) || guardedOrClamped(opnd) || (withoutCasts(opnd) match
      case i: Identifier => clampedByRedefinition(i)
      case _             => false
    )
    guarded || (withoutCasts(opnd) match
      case i: Identifier =>
          site.method.parameter.nameExact(i.name).headOption.exists { param =>
            val callers = param.method._callIn.collectAll[Call].l.distinct
            callers.nonEmpty && callers.forall { callSite =>
                callSite.argumentOption(param.index).collect { case e: Expression => e }
                    .exists { arg =>
                        IndexRange.literal(arg).isDefined ||
                        variableKey(arg).exists(k =>
                            guardBounds(callSite, k, above = true) ||
                                guardBounds(callSite, k, above = false)
                        ) || arg.tag.name(GuardPass.TagAbove).nonEmpty ||
                        arg.tag.name(GuardPass.TagBelow).nonEmpty
                    }
            }
          }
      case _ => false
    )
  end operandKeptInType

  /** The operand's own expression guards it: the `bounded-above`/`bounded-below` tag GuardPass left
    * on it, or a clamp in the statement's own expression (`data & 0x7f`, `data % 100`, a min/max
    * conditional, the inventory's clamp).
    */
  private def guardedOrClamped(op: Expression): Boolean =
      op.tag.name(GuardPass.TagAbove).nonEmpty || op.tag.name(GuardPass.TagBelow).nonEmpty ||
          op.tag.name(MemoryApiPass.TagClamp).nonEmpty || {
              var cursor: Option[StoredNode] = op._astIn.nextOption()
              var found                      = false
              while !found && cursor.exists(_.isInstanceOf[Expression]) do
                val parent = cursor.get
                parent match
                  case c: Call =>
                      found = c.name match
                        case "<operator>.and" | "<operator>.modulo"      => true
                        case "<operator>.conditional" | "<operator>.min" => true
                        case "<operator>.max"                            => true
                        case _                                           => false
                  case _ => ()
                cursor = parent._astIn.nextOption()
              found
          }

  private def fitsType(v: BigInt, t: String): Boolean =
      IndexRange.fitsType(v, t) || (integralWidth(t) match
        case Some(w) if isUnsignedIntegral(t) => v >= 0 && v <= (BigInt(1) << w) - 1
        case Some(w) => v >= -(BigInt(1) << (w - 1)) && v <= (BigInt(1) << (w - 1)) - 1
        case None    => false
      )

  /** The declared type of the variable an operation's result is stored into: `char result = data +
    * 1` keeps a char, whatever width the addition computed in.
    */
  private def storeDestinationOf(c: Call): Option[String] =
      c._astIn.collectFirst { case a: Call => a }.flatMap {
          case a if a.name == "<operator>.assignment" && a.argumentOption(2).exists(_.id == c.id) =>
              a.argumentOption(1).collect { case i: Identifier => i }
                  .map(i => String.valueOf(i.property("TYPE_FULL_NAME")).trim)
                  .filter(t => t.nonEmpty && t != "ANY")
          case _ => None
      }

  /** A widened operand makes the wrap impossible in the kept type: `(long long)a + b` computes at
    * 64 bits, and a 64-bit accumulator is the wide-type twin however wide the inputs are.
    */
  private def widenedBeyond(c: Call, keptIn: String): Boolean =
      integralWidth(keptIn).exists(kw =>
          kw >= 64 || operandsOf(c).exists {
              case cast: Call if cast.name == "<operator>.cast" =>
                  val target = String.valueOf(cast.property("TYPE_FULL_NAME")).trim
                  integralWidth(target).exists(tw => tw >= 64 && tw >= kw)
              case _ => false
          }
      )

  /** MS-INT-003 (CWE-190, and the CWE-191 direction of the same arithmetic): an operation whose
    * result can leave the type it is kept in.
    */
  def arithmeticOverflow(
    atom: Cpg,
    record: (StoredNode, String) => Unit
  ): List[(StoredNode, String, Boolean)] =
    val promoted = mutable.ListBuffer.empty[(StoredNode, String, Boolean)]
    // an operand whose definitions bound its value well inside the type - a masked field
    // plus one - cannot carry the sum past it
    def smallValue(o: Expression): Boolean =
        rangesOf(atom.graph, o).exists(r =>
            r.hi < (BigInt(1) << 30) && r.lo > -(BigInt(1) << 30)
        )
    atom.method.filterNot(m => m.isExternal || m.name == "<global>").l.foreach { method =>
        method.ast.isCall.l.foreach { c =>
          val keptIn = storeDestinationOf(c).getOrElse(c.typeFullName)
          // the wrap's direction names its CWE: below the type's floor is CWE-191 (its
          // own rule id, the same evidence), above the ceiling CWE-190
          val underflow: Boolean = c.name match
            case "<operator>.postDecrement" | "<operator>.preDecrement" => true
            case "<operator>.minus"                                     => true
            case "<operator>.subtraction" =>
                operandsOf(c).exists(x =>
                    constantOf(x).exists(_ < 0) ||
                        (withoutCasts(x) match
                          case i: Identifier => constantDefOf(i).exists(_ < 0)
                          case _             => false
                        )
                )
            case _ => false
          val found: Option[(Expression, Boolean)] = c.name match
            case op if ArithOps.contains(op) =>
                val ops    = operandsOf(c)
                val consts = ops.map(constantOf)
                if consts.nonEmpty && consts.forall(_.isDefined) then
                  val values = consts.map(_.get)
                  val exact = op match
                    case "<operator>.addition"       => Some(values.sum)
                    case "<operator>.subtraction"    => Some(values.reduceLeft(_ - _))
                    case "<operator>.multiplication" => Some(values.product)
                    case "<operator>.minus"          => values.headOption.map(-_)
                    case _                           => None
                  // even a constant wraps only where nothing keeps it in type: the
                  // good twins guard the extremes (`if (data > CHAR_MIN) data--`), and
                  // the guard is the author's own answer to the same question. And the
                  // wrap the ARITHMETIC can suffer is measured against the promoted
                  // computation type - its width AND signedness (C computes `uint8 +
                  // uint8` at int, and `int + unsigned` at unsigned int): a result that
                  // fits the computation and only overflows the STORE is the conversion
                  // question, and a wrap inside an unsigned computation is modular
                  // arithmetic the language defines
                  val guarded   = ops.exists(operandKeptInType(c, _))
                  val opndTypes = ops.map(operandComputationType)
                  val width     = math.max(opndTypes.map(_._1).max, 32)
                  // the frontend's own type for the computation counts too: a macro's
                  // `(size_t)1 << 60` operand may reach here untyped while the product is size_t
                  val unsigned = opndTypes.exists((w, u) => u && w == width) ||
                      isUnsignedIntegral(c.typeFullName)
                  exact
                      .filter(v => !unsigned && leavesSignedComputation(v, width))
                      .filter(_ => !guarded)
                      .map(_ => (c, true))
                else
                  // the input arm asks the same question the definite arm does: a wrap of a
                  // SIGNED computation (an unsigned one is modular arithmetic the language
                  // defines), and one an operand masked into a small range cannot reach
                  val opndTypes = ops.map(operandComputationType)
                  val width     = math.max(opndTypes.map(_._1).max, 32)
                  val unsigned = opndTypes.exists((w, u) => u && w == width) ||
                      isUnsignedIntegral(c.typeFullName)
                  val masked = ops.exists(o =>
                      withoutCasts(o) match
                        case and: Call if and.name == "<operator>.and" =>
                            and.argument.l.collect { case e: Expression => e }
                                .flatMap(IndexRange.literal)
                                .exists(m => m >= 0 && m < (BigInt(1) << 30))
                        case _ => false
                  )
                  // pointer arithmetic (`ptr + len`, a `char*` result): the sum moves an
                  // address, it does not wrap an integer type
                  val pointerArith = isPointer(String.valueOf(c.property("TYPE_FULL_NAME")).trim) ||
                      ops.exists(o => isPointer(operandTypeOf(o)))
                  ops.find(opnd =>
                      !pointerArith && !unsigned && !masked && !booleanSum(opnd, 3, Set.empty) &&
                          !isPointer(operandTypeOf(opnd)) && inputFed(opnd) &&
                          !lengthDerived(opnd) && !smallValue(opnd)
                  ).filter { opnd =>
                      !operandKeptInType(c, opnd) && !widenedBeyond(c, keptIn)
                  }.map(opnd => (c, false))
                end if
            case inc if IncrementOps.contains(inc) =>
                c.argumentOption(1).collect { case i: Identifier => i }.flatMap { i =>
                  val kept = storeDestinationOf(c).getOrElse(i.typeFullName)
                  // the kept type must be a width the frontends name: `time_t`, a reference
                  // parameter's `int&`, a typedef'd `size_type` or an unresolved member type
                  // is not a width, and "does not fit an unknown type" is not a fact
                  val knownKept = integralWidth(kept).isDefined
                  constantDefOf(i).flatMap { v =>
                    val next = if inc.endsWith("Increment") then v + 1 else v - 1
                    // the wrap is asked of the PROMOTED computation (C computes `u--` at
                    // int however narrow the stored type), and only where that computation
                    // is signed: an unsigned wrap is defined modular arithmetic, and the
                    // store's conversion is the conversion rule's question
                    val (pw, pu) = operandComputationType(i)
                    Option.when(
                      knownKept && !pu && leavesSignedComputation(next, pw) &&
                          !operandKeptInType(c, i)
                    )(i)
                  }.orElse(
                    Option.when(
                      !isPointer(i.typeFullName) && !booleanTyped(i) &&
                          inputFed(i) && !smallValue(i) && !operandKeptInType(
                            c,
                            i
                          ) && !widenedBeyond(
                            c,
                            kept
                          )
                    )(i)
                  ).map(i => (i, constantDefOf(i).isDefined))
                }
            case _ => None
          found.foreach { case (node, definite) =>
              val goesBelow = c.name match
                case "<operator>.postDecrement" | "<operator>.preDecrement" => true
                case "<operator>.minus"                                     => true
                case "<operator>.subtraction" =>
                    operandsOf(c).exists(x =>
                        constantOf(x).exists(_ < 0) ||
                            (withoutCasts(x) match
                              case i: Identifier => constantDefOf(i).exists(_ < 0)
                              case _             => false
                            )
                    )
                case _ => false
              val rule = if goesBelow then RuleArithmeticUnderflow else RuleArithmeticOverflow
              record(node, rule)
              promoted += ((node, rule, definite))
          }
        }
    }
    promoted.toList
  end arithmeticOverflow

  /** The type an operand is kept in, casts aside: the pointer test the step arms ask reads this. */
  private def operandTypeOf(opnd: Expression): String =
      String.valueOf(opnd.property("TYPE_FULL_NAME")).trim

  /** A boolean-typed operand, or one that IS a comparison or a logical operation - through the
    * conversion that carries it into the arithmetic (`static_cast<int>(s.empty()) - 1`): `flag + 1`
    * and `a + (b != c)` compute in {0, 1} - arithmetic the language bounds, not a wrap the input
    * chooses.
    */
  private def booleanTyped(opnd: Expression): Boolean =
    val bare = withoutCasts(opnd)
    val t    = operandTypeOf(bare)
    val throughCast = opnd match
      case c: Call if c.name == "<operator>.cast" =>
          c.argumentOption(2).orElse(c.argumentOption(1)).collect { case e: Expression => e }
      case _ => None
    Set("bool", "_Bool", "BOOL", "boolean").contains(t) ||
    (bare match
      case c: Call => BooleanOps.contains(c.name)
      case _       => false
    ) || throughCast.exists(booleanTyped)

  /** A variable every definition of which is boolean arithmetic: the sum of comparisons counts
    * matches (`n = (a != NULL) + (b != NULL)`), a value in [0, N] by construction.
    */
  private def booleanFed(opnd: Expression, depth: Int, seen: Set[String]): Boolean =
      withoutCasts(opnd) match
        case i: Identifier if depth >= 0 && !seen.contains(i.name) =>
            val rhss = reachingDefsIn(i)
                .collect { case d: Identifier if d.name == i.name => d }
                .flatMap(d =>
                    d._astIn.collectFirst {
                        case a: Call
                            if a.name == "<operator>.assignment" &&
                                a.argumentOption(1).exists(_.id == d.id) =>
                            a.argumentOption(2).collect { case e: Expression => e }
                    }.toList.flatten
                )
            rhss.nonEmpty && rhss.forall(booleanSum(_, depth, seen + i.name))
        case _ => booleanTyped(opnd)

  private def booleanSum(e: Expression, depth: Int, seen: Set[String]): Boolean =
      booleanTyped(e) || (depth > 0 && (withoutCasts(e) match
        case c: Call if ArithOps.contains(c.name) =>
            c.argument.l.collect { case x: Expression => x }
                .forall(booleanSum(_, depth - 1, seen))
        // the variable a definition writes is another nesting level of the same question,
        // not a descent: the budget is spent on the expression, not the spelling - a self-
        // referential chain (`n = n + 1`) ends at the seen set
        case i: Identifier => booleanFed(i, depth, seen)
        case _             => false
      ))

  /** The width the operand's value computes in: its own declared type, arithmetic promoted to at
    * least 32 bits. A cast WIDER than this converts nothing away.
    */
  private def computedWidthOfOpnd(opnd: Expression): Option[Int] =
      promotedTypeOf(opnd).map(_._1)

  /** The computation an operand takes part in: its width (promoted to at least 32 bits) and its
    * signedness. A cast's own target governs when the graph knows it - `(uint64_t)1000000000`
    * computes at 64 bits however narrow the literal spells - and the operand's declared type
    * otherwise. Signedness travels with the width, because C's usual arithmetic conversions make
    * the computation UNSIGNED whenever an operand of the governing width is unsigned.
    */
  private def promotedTypeOf(opnd: Expression): Option[(Int, Boolean)] =
    def ofType(t: String): Option[(Int, Boolean)] =
        integralWidth(t).filter(_ > 0).map(w => (math.max(w, 32), isUnsignedIntegral(t)))
    opnd match
      case cast: Call if cast.name == "<operator>.cast" =>
          val target = String.valueOf(cast.property("TYPE_FULL_NAME")).trim
          ofType(target).orElse(
            cast.argumentOption(2).orElse(cast.argumentOption(1)).collect {
                case e: Expression => e
            }.flatMap(promotedTypeOf)
          )
      case other =>
          ofType(String.valueOf(other.property("TYPE_FULL_NAME")).trim).orElse(other match
            // an operator the frontend left untyped takes its operands' computation: a shift
            // computes in its left operand's type (`(size_t)1 << 60` is size_t), the binary
            // arithmetic in the usual conversion of both
            case c: Call
                if c.name == "<operator>.shiftLeft" || c.name == "<operator>.arithmeticShiftRight" =>
                c.argumentOption(1).collect { case e: Expression => e }.flatMap(promotedTypeOf)
            case c: Call if ArithOps.contains(c.name) =>
                val parts = operandsOf(c).flatMap(promotedTypeOf)
                Option.when(parts.nonEmpty) {
                    val w = parts.map(_._1).max
                    (w, parts.exists((pw, pu) => pu && pw == w))
                }
            case _ => None
          )
    end match
  end promotedTypeOf

  /** The computation an operand takes part in, with the literal ladder as the fallback: a constant
    * the frontends left untyped (`ULONG_MAX`'s macro body, its node typed ANY) keeps the signedness
    * its own value states in C - a positive literal above the signed 64-bit ceiling is an unsigned
    * 64-bit constant, whatever the type field says.
    */
  private def operandComputationType(opnd: Expression): (Int, Boolean) =
    def ladder(v: BigInt): (Int, Boolean) =
        if v >= 0 then (if v <= (BigInt(1) << 62) then (64, false) else (64, true))
        else (64, false)
    def fitsSignedWidth(v: BigInt, w: Int): Boolean =
        v >= -(BigInt(1) << (w - 1)) && v <= (BigInt(1) << (w - 1)) - 1
    promotedTypeOf(opnd) match
      case Some((w, u)) =>
          // a constant the frontend FOLDED carries its own value, and the value outranks
          // the type the macro expansion's arithmetic was left with: the min/max limits
          // are typed `int` by the expander and folded to -2^63 by the evaluator, and C's
          // constant ladder computed them at the width that fits or the header would not
          // compile. The evaluator applies C's semantics when it folds program arithmetic,
          // so a value the declared width cannot hold names the expander's type guess,
          // not a wrap the program can suffer
          IndexRange.literal(opnd).filter(v => !fitsSignedWidth(v, w)) match
            case Some(v) => ladder(v)
            case None    => (w, u)
      case None =>
          IndexRange.literal(opnd).map(ladder).getOrElse((32, false))
  end operandComputationType

  /** A value leaves a SIGNED computation of the given width: the only wrap the definite arm
    * reports. An unsigned computation wraps by modular arithmetic the language defines, and the
    * model checker's own default check is the signed one - the `SIZE_MAX - k` guards and every `MAX
    * * 2U + 1U` header constant compute unsigned on purpose.
    */
  private def leavesSignedComputation(v: BigInt, width: Int): Boolean =
      v < -(BigInt(1) << (width - 1)) || v > (BigInt(1) << (width - 1)) - 1

  /** MS-CONV-001 (CWE-197): a narrowing cast of a value that can exceed the target - an input the
    * program read, or a constant that does not fit.
    */
  /** A value built from bit operations - a mask cleared or built (`flags &= (uint8_t)~MASK`), a
    * field split out of a wider constant (`(uint32_t)(MAGIC >> 32)`) - narrows to its low bits by
    * construction: the truncation IS the idiom's meaning, not a value the conversion loses.
    */
  private def bitBuiltValue(e: Expression, depth: Int = 8): Boolean = e match
    case c: Call =>
        c.name match
          case "<operator>.and" | "<operator>.or" | "<operator>.xor" | "<operator>.not" |
              "<operator>.shiftLeft" | "<operator>.shiftRight" |
              "<operator>.arithmeticShiftRight" | "<operator>.logicalShiftRight" =>
              true
          case "<operator>.cast" =>
              c.argumentOption(2).orElse(c.argumentOption(1)).collect {
                  case x: Expression => x
              }.exists(bitBuiltValue(_, depth - 1))
          case op if op.startsWith("<operator>") && depth > 0 =>
              c.argument.l.collect { case x: Expression => x }.exists(bitBuiltValue(_, depth - 1))
          case _ => false
    case _ => false

  def narrowingConversion(
    atom: Cpg,
    record: (StoredNode, String) => Unit
  ): List[(StoredNode, String, Boolean)] =
    val promoted = mutable.ListBuffer.empty[(StoredNode, String, Boolean)]
    atom.call.name("<operator>.cast").l.foreach { cast =>
      val target = String.valueOf(cast.property("TYPE_FULL_NAME")).trim
      val operand = cast.argumentOption(2).orElse(cast.argumentOption(1)).collect {
          case e: Expression => e
      }
      operand.foreach { opnd =>
        val fromWidth = computedWidthOfOpnd(opnd)
        for tw <- integralWidth(target); fw <- fromWidth if tw < fw do
          val exceeds = constantOf(opnd).exists(v => !fitsType(v, target))
          val input   = inputFed(opnd)
          if (exceeds || input) && !operandKeptInType(cast, opnd) && !bitBuiltValue(opnd) then
            record(cast, RuleNarrowingConversion)
            promoted += ((cast, RuleNarrowingConversion, exceeds))
      }
    }
    promoted.toList
  end narrowingConversion

  /** MS-CONV-002 (CWE-194): a possibly-negative signed input value in an unsigned size position -
    * the inventory's `len` roles: an allocation size, a copy length, `strncpy`'s count. The
    * operand's own declared type carries the signedness.
    */
  def signExtensionToSize(
    atom: Cpg,
    record: (StoredNode, String) => Unit
  ): List[(StoredNode, String, Boolean)] =
    val promoted = mutable.ListBuffer.empty[(StoredNode, String, Boolean)]
    OverlayFacts
        .memoryArgumentSites(atom)
        .collect { case (call, arg, MemoryApiPass.TagLen) => (call, arg) }
        .foreach { case (call, lenArg) =>
            withoutCasts(lenArg) match
              case i: Identifier =>
                  val t = String.valueOf(i.property("TYPE_FULL_NAME")).trim
                  if t.nonEmpty && t != "ANY" && isSignedIntegral(t) then
                    val negativeConstant = constantOf(i).exists(_ < 0)
                    val input            = inputFed(i)
                    val boundedBelow = i.tag.name(GuardPass.TagBelow).nonEmpty ||
                        variableKey(i).exists(k => guardBounds(call, k, above = false))
                    val nonNegative = rangesOf(atom.graph, i).exists(_.lo >= 0)
                    if (negativeConstant || input) && !boundedBelow && !nonNegative then
                      record(lenArg, RuleSignExtensionToSize)
                      promoted += ((lenArg, RuleSignExtensionToSize, negativeConstant))
              case _ => ()
        }
    promoted.toList
  end signExtensionToSize

end ArithmeticRules
