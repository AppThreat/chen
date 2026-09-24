package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS-INVAL-001 (CWE-416, part 9): a view into a std container - an iterator, a reference or a
  * pointer - used after a call that may reallocate or restructure the SAME container, with no
  * re-take in between. The C++ standard makes every iterator, reference and pointer into a
  * vector or a string dangling when the container reallocates (`push_back`, `emplace_back`,
  * `insert`, `resize`, `reserve`) or restructures its storage (`erase`, `clear`, `assign`);
  * using one afterwards reads or writes freed storage - use-after-free over an invalidation
  * rather than an explicit free.
  *
  * Everything here is read off the shapes the C frontend leaves for C++ member calls - `v.begin()`
  * is a call `begin` whose first argument is the receiver, `v.push_back(x)` a call `push_back`
  * over the same receiver - so the rule never needs a type table the frontend does not have:
  *
  *   - a VIEW is an assignment `x = <take>` where the take is `begin/end/.../front/back/data/
  *     c_str/at(v)` or `v[i]` (through `&` and casts), and `v` an identifier - the container is
  *     whatever the member call received;
  *   - an INVALIDATION is a member call on that same identifier from the invalidator family;
  *   - a USE is any later appearance of `x` except the assignment that re-takes it (a re-take
  *     rebinds the view; `it = v.begin()` after the push_back is the fix, not the bug). A write
  *     through a reference (`first = 7`) is a use exactly as a dereference of an iterator is.
  *
  * The reserve idiom stands down for the amortised-growth calls only: `v.reserve(n)` before the
  * view was taken makes `push_back`/`emplace_back`/`insert` non-reallocating, while `erase`,
  * `clear`, `assign` and any later `reserve`/`resize` invalidate whatever the capacity is.
  *
  * The reference-PARAMETER arm is a hypothesis the graph cannot settle: in
  * `void f(vector<int> &v, int &elem)` whether `elem` is bound into `v`'s storage is a caller's
  * choice, so a use of `elem` after `v` was modified reports at LOW confidence (the finding's
  * own tier, not the rule's). A by-value parameter or a plain C pointer parameter is out - the
  * code carries no `&` - and a container modified in this frame cannot be what a caller-bound
  * reference points into, so that arm only reads containers that are parameters or globals.
  */
object ContainerInvalidationRules:

  /** member calls whose result is a view into their receiver. */
  private val ViewTakers =
    Set("begin", "end", "rbegin", "rend", "cbegin", "cend", "front", "back", "data", "c_str", "at")

  /** member calls that may reallocate or restructure their receiver (`append` is std::string's
    * growth call - the same reallocation `push_back` performs on a vector).
    */
  private val Invalidators =
    Set("push_back", "emplace_back", "insert", "resize", "reserve", "erase", "clear", "assign",
      "append")

  /** member calls that invalidate and RETURN a fresh valid iterator: `it = v.erase(it)` is the
    * fix idiom, a re-take rather than a use.
    */
  private val RetakingInvalidators = Set("erase", "insert", "emplace")

  /** the growth family: a `reserve` before the view was taken makes these non-reallocating. */
  private val GrowthFamily = Set("push_back", "emplace_back", "insert", "append")

  /** `std::vector<int> &v`, `vector<Foo*> v`: the element type of a vector/string parameter. */
  private val ContainerElement = """(?:std::)?(?:vector|deque)\s*<\s*(.+)>\s*&?\s*\w+\s*$""".r
  private val StringParam      = """(?:std::)?string\s*&\s*\w+\s*$""".r

  /** `int &elem`, `const char &c`: a reference parameter's referent type. */
  private val RefParam = """^(.+?)\s*&\s*\w+\s*$""".r

  private def normaliseType(t: String): String =
      t.replaceAll("\\bconst\\b", "").replaceAll("\\s+", "")

  private final case class View(name: String, base: String, takeLine: Int)
  private final case class Invalidation(base: String, line: Int, growth: Boolean)
  private final case class Use(node: Identifier, line: Int)

  /** The receiver identifier a member-call shape names, through casts: `begin(v)`, `(T) begin(v)`.
    * A C++ member call the C frontend laid down keeps its receiver at argument index 0 (an
    * operator's operands sit at 1 and 2), so the receiver is the LOWEST-indexed argument.
    */
  private def receiverOf(c: Call): Option[String] =
      c.argument.l.sortBy(_.argumentIndex).collectFirst { case i: Identifier => i.name }

  /** The container a take expression looks into, through `&` and casts: `v.begin()`, `v[0]`,
    * `&v[0]`, `(int *) &v[0]`.
    */
  private def viewBase(e: Expression): Option[String] = e match
    case c: Call =>
        c.name match
            case "<operator>.cast" | "<operator>.addressOf" =>
                c.argument.l.collect { case x: Expression => x }.lastOption.flatMap(viewBase)
            case "<operator>.indexAccess" | "<operator>.indirectIndexAccess" => receiverOf(c)
            case name if ViewTakers.contains(name) || RetakingInvalidators.contains(name) =>
                receiverOf(c)
            case _ => None
    case _ => None

  private def lineOf(n: AstNode): Int = n match
      case e: Expression => e.lineNumber.map(_.toInt).getOrElse(-1)
      case _             => -1

  /** Is this identifier the target of an assignment whose rhs re-takes a view (`it = v.begin()`)?
    * That statement is a birth, not a use.
    */
  private def isRetakeTarget(i: Identifier): Boolean =
      i._astIn.collectFirst { case c: Call => c }.exists { parent =>
          parent.name == "<operator>.assignment" &&
          parent.argumentOption(1).exists(_.id == i.id) &&
          parent.argumentOption(2).collect { case e: Expression => e }.exists(e => viewBase(e).isDefined)
      }

  /** The rule: reports on the first use of each dangling view, and returns the nodes whose
    * finding is the may-alias reference-parameter arm (the caller lowers those to `low`).
    */
  def containerInvalidation(atom: Cpg, record: (StoredNode, String) => Unit): Set[StoredNode] =
    // one indexed lookup: a C tree carries none of these member names and never enters the loop
    if atom.call.name((ViewTakers ++ Invalidators).mkString("|")).l.isEmpty then return Set.empty
    val hypothesis = mutable.LinkedHashSet.empty[StoredNode]
    atom.method.isExternal(false).filterNot(_.name == "<global>").l.foreach { m => analyse(m, record, hypothesis) }
    hypothesis.toSet

  private def analyse(
      method: Method,
      record: (StoredNode, String) => Unit,
      hypothesis: mutable.LinkedHashSet[StoredNode]
  ): Unit =
    val views        = mutable.ListBuffer.empty[View]
    val invalidations = mutable.ListBuffer.empty[Invalidation]
    val reserves      = mutable.ListBuffer.empty[(String, Int)] // (base, line)
    method.ast.collectAll[Call].l.foreach { c =>
        val line = lineOf(c)
        if line >= 0 then
            c.name match
                case "<operator>.assignment" =>
                    (c.argumentOption(1).collect { case i: Identifier => i.name },
                      c.argumentOption(2).collect { case e: Expression => e }) match
                        case (Some(target), Some(rhs)) =>
                            viewBase(rhs).foreach(base => views += View(target, base, line))
                        case _ => ()
                case name if Invalidators.contains(name) =>
                    receiverOf(c).foreach { base =>
                        invalidations += Invalidation(base, line, GrowthFamily.contains(name))
                        if name == "reserve" then reserves += ((base, line))
                    }
                case _ => ()
    }
    if views.isEmpty && invalidations.isEmpty then return

    // the uses of every tracked view name - any appearance except the take/re-take assignment
    val viewNames = views.map(_.name).toSet
    val usesByName: Map[String, List[Use]] =
        method.ast.collectAll[Identifier].l
            .filter(i => viewNames.contains(i.name) && lineOf(i) >= 0 && !isRetakeTarget(i))
            .groupMap(_.name)(i => Use(i, lineOf(i)))
            .view
            .mapValues(_.sortBy(_.line))
            .toMap

    // the arm-1 report: the first use of each view after the first unexcused invalidation of
    // its container, before the view's name was re-taken
    views.foreach { v =>
        def excused(inv: Invalidation): Boolean =
            inv.growth && inv.base == v.base &&
            reserves.exists { case (b, r) =>
                b == v.base && r < v.takeLine &&
                !invalidations.exists(i =>
                    i.base == v.base && !i.growth && r < i.line && i.line < inv.line
                )
            }
        val nextTake = views.filter(w => w.name == v.name && w.takeLine > v.takeLine)
            .map(_.takeLine).sorted.headOption.getOrElse(Int.MaxValue)
        invalidations
            .filter(i => i.base == v.base && i.line > v.takeLine && !excused(i))
            .map(_.line).sorted.headOption.foreach { invLine =>
                usesByName.get(v.name).foreach { uses =>
                    uses.find(u => u.line > invLine && u.line < nextTake)
                        .foreach(u => record(u.node, MemorySafetyFindingPass.RuleContainerInvalidation))
                }
            }
    }

    // arm 2: a reference parameter used after a container PARAMETER was modified - whether the
    // caller bound the reference into that container cannot be seen from here. Only a
    // reference to the container's own element type can be bound into it: `int &elem` beside
    // `vector<int> &v`, never `Item &item`
    val elementTypeOf: Map[String, String] = method.parameter.l.flatMap { p =>
        ContainerElement.findFirstMatchIn(p.code).map(m => p.name -> normaliseType(m.group(1)))
            .orElse(StringParam.findFirstMatchIn(p.code).map(_ => p.name -> "char"))
    }.toMap
    val invalidatedElements = invalidations.flatMap(i => elementTypeOf.get(i.base)).toSet
    val refParams = method.parameter.l
        .filterNot(p => elementTypeOf.contains(p.name))
        .flatMap(p => RefParam.findFirstMatchIn(p.code).map(m => p.name -> normaliseType(m.group(1))))
        .collect { case (name, t) if invalidatedElements.contains(t) => name }
        .toSet
    if refParams.nonEmpty then
        val paramUses: Map[String, List[Use]] =
            method.ast.collectAll[Identifier].l
                .filter(i => refParams.contains(i.name) && lineOf(i) >= 0 && !isRetakeTarget(i))
                .groupMap(_.name)(i => Use(i, lineOf(i)))
                .view
                .mapValues(_.sortBy(_.line))
                .toMap
        invalidations
            .filter(i => elementTypeOf.contains(i.base))
            .map(_.line).sorted.headOption.foreach { invLine =>
                refParams.foreach { p =>
                    paramUses.get(p).foreach { uses =>
                        uses.find(u => u.line > invLine).foreach { u =>
                            record(u.node, MemorySafetyFindingPass.RuleContainerInvalidation)
                            hypothesis += u.node
                        }
                    }
                }
            }
    end if
  end analyse
