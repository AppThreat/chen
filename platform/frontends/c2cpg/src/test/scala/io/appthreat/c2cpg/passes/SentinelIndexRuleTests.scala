package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.{DataFlowCodeToCpgSuite, DataFlowTestCpg}
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    IntegerWidthPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    MemorySemanticsPass,
    ValueOriginPass
}
import io.shiftleft.semanticcpg.language.*

/** MS-BOUND-011: the sentinel index. A subscript indexed by a lookup's not-found answer (a `return
  * -1;` path) or by an expression that can evaluate to a negative constant, with no dominating
  * guard bounding the index below, reports without a known extent; the checked variants stand down.
  * The suite runs the same C file twice: once with `assert` left unresolved (no headers), once with
  * it macro-expanded the way glibc spells the expansion - an assert is not a guard in a release
  * build, so the expanded form must change nothing.
  */
class SentinelIndexRuleTests extends DataFlowCodeToCpgSuite:

  private val repro =
      """
      |typedef struct obj { long r; } obj;
      |extern obj *call_one(obj *a);
      |static long tuple_index(obj **items, long n, obj *x) {
      |    for (long i = 0; i < n; i++) if (items[i] == x) return i;
      |    return -1;
      |}
      |obj *noassert(obj **p, long n, obj **argitems, obj *x) {
      |    long i = tuple_index(p, n, x);
      |    return call_one(argitems[i]);
      |}
      |obj *withassert(obj **p, long n, obj **argitems, obj *x) {
      |    long i = tuple_index(p, n, x);
      |    assert(i >= 0);
      |    return call_one(argitems[i]);
      |}
      |obj *direct(obj **argitems, int c) {
      |    long i = c ? 3 : -1;
      |    return call_one(argitems[i]);
      |}
      |obj *guarded(obj **p, long n, obj **argitems, obj *x) {
      |    long i = tuple_index(p, n, x);
      |    if (i < 0) return 0;
      |    return call_one(argitems[i]);
      |}
      |obj *equality_checked(obj **p, long n, obj **argitems, obj *x) {
      |    long i = tuple_index(p, n, x);
      |    if (i == -1) return 0;
      |    return call_one(argitems[i]);
      |}
      |obj *not_equals_checked(obj **p, long n, obj **argitems, obj *x) {
      |    long i = tuple_index(p, n, x);
      |    if (i != -1) return call_one(argitems[i]);
      |    return 0;
      |}
      |obj *guard_with_assert_and_return(obj **p, long n, obj **argitems, obj *x) {
      |    long i = tuple_index(p, n, x);
      |    if (i < 0) {
      |        assert(0);
      |        return 0;
      |    }
      |    return call_one(argitems[i]);
      |}
      |void assert_inside_guard(obj **p, long n, obj **argitems, obj *x) {
      |    long i = tuple_index(p, n, x);
      |    if (i >= 0) {
      |        assert(i < n);
      |        argitems[i] = x;
      |    }
      |}
      |enum { IX_EMPTY = -1 };
      |static long dict_lookup(obj **items, long n, obj *x) {
      |    for (long i = 0; i < n; i++) if (items[i] == x) return i;
      |    return IX_EMPTY;
      |}
      |obj *named_sentinel_checked(obj **p, long n, obj **argitems, obj *x) {
      |    long i = dict_lookup(p, n, x);
      |    if (i == IX_EMPTY) return 0;
      |    return call_one(argitems[i]);
      |}
      |obj *named_sentinel_unchecked(obj **p, long n, obj **argitems, obj *x) {
      |    long i = dict_lookup(p, n, x);
      |    return call_one(argitems[i]);
      |}
      |obj *unsigned_checked(obj **p, long n, obj **argitems, obj *x) {
      |    long i = tuple_index(p, n, x);
      |    if ((unsigned) i >= (unsigned) n) return 0;
      |    return call_one(argitems[i]);
      |}
      |""".stripMargin

  private val unresolvedAssertCpg: DataFlowTestCpg = new DataFlowTestCpg()
      .moreCode(repro, "sentinel.c")

  // the expansion has to live in the translation unit the assert is written in: a define in
  // an included header does not reach the parser here
  private val expandedAssertCpg: DataFlowTestCpg = new DataFlowTestCpg()
      .moreCode(
        s"""|#define assert(e) ((e) ? (void)0 : __assert_fail(#e, __FILE__, __LINE__, __func__))
            |extern void __assert_fail(const char *, const char *, int, const char *);
            |$repro""".stripMargin,
        "sentinel_expanded.c"
      )

  // the other expansion spelling: an `if` whose aborting branch holds the noreturn call
  private val ifFormAssertCpg: DataFlowTestCpg = new DataFlowTestCpg()
      .moreCode(
        s"""|#define assert(e) if (!(e)) __assert_fail(#e, __FILE__, __LINE__, __func__)
            |extern void __assert_fail(const char *, const char *, int, const char *);
            |$repro""".stripMargin,
        "sentinel_if_expanded.c"
      )

  private def applyPasses(cpg: DataFlowTestCpg): Unit =
    new MemorySemanticsPass(cpg).createAndApply()
    new MemoryApiPass(cpg).createAndApply()
    new ExtentPass(cpg).createAndApply()
    new GuardPass(cpg).createAndApply()
    new ValueOriginPass(cpg).createAndApply()
    new IntegerWidthPass(cpg).createAndApply()
    new AllocationStatePass(cpg).createAndApply()
    new MemorySafetyFindingPass(cpg).createAndApply()

  /** Rule ids on the index arguments of the method's array accesses. */
  private def indexFindings(cpg: DataFlowTestCpg, method: String): Set[String] =
      cpg.method
          .name(method)
          .call
          .name("<operator>.indexAccess|<operator>.indirectIndexAccess")
          .l
          .flatMap(_.argumentOption(2))
          .flatMap(_.tag.name("ms-finding").value.l)
          .toSet

  "MS-BOUND-011 with assert unresolved" should:

    applyPasses(unresolvedAssertCpg)

    "fire on the unchecked lookup result" in:
      indexFindings(unresolvedAssertCpg, "noassert") shouldBe Set("MS-BOUND-011")

    "fire on the lookup result whose only check is an assert" in:
      indexFindings(unresolvedAssertCpg, "withassert") shouldBe Set("MS-BOUND-011")

    "fire on an expression that can evaluate to a negative constant" in:
      indexFindings(unresolvedAssertCpg, "direct") shouldBe Set("MS-BOUND-011")

    "not fire when a guard bounds the index below" in:
      indexFindings(unresolvedAssertCpg, "guarded") shouldBe empty

    "keep a real guard whose branch also asserts" in:
      indexFindings(unresolvedAssertCpg, "guard_with_assert_and_return") shouldBe empty
      indexFindings(unresolvedAssertCpg, "assert_inside_guard") shouldBe empty

    "follow a sentinel spelled as a named constant" in:
      indexFindings(unresolvedAssertCpg, "named_sentinel_unchecked") shouldBe Set("MS-BOUND-011")
      indexFindings(unresolvedAssertCpg, "named_sentinel_checked") shouldBe empty

    "not fire when an equality rules the sentinel out" in:
      indexFindings(unresolvedAssertCpg, "equality_checked") shouldBe empty
      indexFindings(unresolvedAssertCpg, "not_equals_checked") shouldBe empty

    "not fire when a cast to an unsigned type bounds the index above" in:
      indexFindings(unresolvedAssertCpg, "unsigned_checked") shouldBe empty

    "not fire when the index is a plain loop counter the loop bounds" in:
      indexFindings(unresolvedAssertCpg, "tuple_index") shouldBe empty

    "tag the assert's comparison guard-debug-only" in:
      val comparisons = unresolvedAssertCpg.method
          .nameExact("withassert")
          .ast
          .isCall
          .name("<operator>.greaterEqualsThan")
          .l
      comparisons.filter(_.tag.name("guard-debug-only").nonEmpty).size shouldBe 1

    "mark the finding's index as bounded only by the debug-only assert" in:
      val idx = unresolvedAssertCpg.method
          .nameExact("withassert")
          .call
          .name("<operator>.indexAccess|<operator>.indirectIndexAccess")
          .l
          .flatMap(_.argumentOption(2))
          .head
      idx.tag.name("ms-debug-guard").l should not be empty

  "MS-BOUND-011 with assert macro-expanded" should:

    applyPasses(expandedAssertCpg)

    "really expand the macro (the fixture is the expanded run it claims to be)" in:
      expandedAssertCpg.method
          .nameExact("withassert")
          .ast
          .isCall
          .nameExact("assert")
          .exists(_.dispatchType == DispatchTypes.INLINED) shouldBe true

    "fire on the lookup result whose only check is the expanded assert" in:
      indexFindings(expandedAssertCpg, "withassert") shouldBe Set("MS-BOUND-011")

    "fire on the unchecked lookup result" in:
      indexFindings(expandedAssertCpg, "noassert") shouldBe Set("MS-BOUND-011")

    "not fire when a guard bounds the index below" in:
      indexFindings(expandedAssertCpg, "guarded") shouldBe empty

    "keep a real guard whose branch also asserts" in:
      indexFindings(expandedAssertCpg, "guard_with_assert_and_return") shouldBe empty
      indexFindings(expandedAssertCpg, "assert_inside_guard") shouldBe empty

    "follow a sentinel spelled as a named constant" in:
      indexFindings(expandedAssertCpg, "named_sentinel_unchecked") shouldBe Set("MS-BOUND-011")
      indexFindings(expandedAssertCpg, "named_sentinel_checked") shouldBe empty

    "tag the expansion's comparison guard-debug-only" in:
      // the macro expansion duplicates the comparison (the inlined call's argument and the
      // ternary's condition are two nodes); both carry the tag
      expandedAssertCpg.method
          .nameExact("withassert")
          .ast
          .isCall
          .name("<operator>.greaterEqualsThan")
          .l
          .filter(_.tag.name("guard-debug-only").nonEmpty) should not be empty

  "MS-BOUND-011 with assert expanded into an if" should:

    applyPasses(ifFormAssertCpg)

    "really expand the macro into a control structure" in:
      ifFormAssertCpg.method
          .nameExact("withassert")
          .ast
          .isControlStructure
          .controlStructureType("IF")
          .nonEmpty shouldBe true

    "fire on the lookup result whose only check is the if-form assert" in:
      indexFindings(ifFormAssertCpg, "withassert") shouldBe Set("MS-BOUND-011")

    "fire on the unchecked lookup result" in:
      indexFindings(ifFormAssertCpg, "noassert") shouldBe Set("MS-BOUND-011")

    "not fire when a guard bounds the index below" in:
      indexFindings(ifFormAssertCpg, "guarded") shouldBe empty

    "keep a real guard whose branch also asserts" in:
      indexFindings(ifFormAssertCpg, "guard_with_assert_and_return") shouldBe empty
      indexFindings(ifFormAssertCpg, "assert_inside_guard") shouldBe empty

    "follow a sentinel spelled as a named constant" in:
      indexFindings(ifFormAssertCpg, "named_sentinel_unchecked") shouldBe Set("MS-BOUND-011")
      indexFindings(ifFormAssertCpg, "named_sentinel_checked") shouldBe empty
end SentinelIndexRuleTests
