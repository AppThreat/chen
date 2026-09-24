package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    ValueOriginPass
}
import io.shiftleft.semanticcpg.language.*

/** MS-NULL-001 (part 5, E3): NULL pointer dereference over the nullable-return facts. Every
  * positive mirrors a corpus row (c/cwe476_null_deref.c) or a litmus site (imfdec.c:258's
  * library-return NULL handed straight to a reader); every negative is the checked variant.
  */
class NullDerefRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |
    |struct node { struct node *next; int v; };
    |
    |/* the cwe476 fixture's unchecked malloc: the producer may return NULL */
    |void bad_unchecked_malloc(size_t n)
    |{
    |    char *p = (char *)malloc(16);
    |    p[0] = 'a';
    |    free(p);
    |}
    |
    |/* the fixture's good pair: the guard narrows before the use */
    |void good_checked_malloc(size_t n)
    |{
    |    char *p = (char *)malloc(16);
    |    if (p == NULL) return;
    |    p[0] = 'a';
    |    free(p);
    |}
    |
    |/* the fixture's check-after-use: strlen reads s, the guard admits it, one line later */
    |size_t bad_check_after_use(char *s)
    |{
    |    size_t n = strlen(s);
    |    if (s == NULL) return 0;
    |    return n;
    |}
    |
    |/* the checked-before-use form of the same function */
    |size_t good_check_before_use(char *s)
    |{
    |    if (s == NULL) return 0;
    |    return strlen(s);
    |}
    |
    |/* the fixture's chained unvalidated parameter (the hypothesis tier) */
    |void bad_chained(struct node *head)
    |{
    |    printf("%d\n", head->next->v);
    |}
    |
    |/* the strchr family: nullable return, no-match NULL */
    |char *bad_unchecked_strchr(const char *s, int c)
    |{
    |    char *hit = strchr(s, c);
    |    return strdup(hit);
    |}
    |
    |char *good_checked_strchr(const char *s, int c)
    |{
    |    char *hit = strchr(s, c);
    |    if (!hit) return NULL;
    |    return strdup(hit);
    |}
    |
    |/* part 6 (F1): writing through an unchecked allocation at an inventoried mem-dst
    |   position IS a dereference - the role the inventory states, not the old blanket
    |   "any argument of a memory call" */
    |void bad_memcpy_unchecked(size_t n)
    |{
    |    char *dst = (char *)malloc(16);
    |    memcpy(dst, "x", 1);
    |    free(dst);
    |}
    |
    |/* part 6 (F1): the length argument of a copy is not a dereference - it is an integer.
    |   The dst is checked here, so nothing may fire */
    |void good_memcpy_checked_len(const char *src, size_t n)
    |{
    |    char *dst = (char *)malloc(16);
    |    if (dst == NULL) return;
    |    memcpy(dst, src, n);
    |    free(dst);
    |}
    |""".stripMargin,
    "null_deref.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  /** (rule id, line) pairs found on any expression of the method. */
  private def findingsIn(method: String): Set[(String, Int)] =
      cpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.Expression]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(a =>
              a.tag.name("ms-finding").value.l.map(v =>
                  (v, a.lineNumber.map(_.toInt).getOrElse(-1))
              )
          )
          .l
          .toSet

  "MS-NULL-001" should:

    "fire on an unchecked allocation result (the cwe476 fixture)" in {
        findingsIn("bad_unchecked_malloc").map(_._1) shouldBe Set("MS-NULL-001")
    }

    "stay silent when a guard narrows the allocation before the use" in {
        findingsIn("good_checked_malloc") shouldBe empty
    }

    "fire when the author's null check comes after the use" in {
        findingsIn("bad_check_after_use").map(_._1) shouldBe Set("MS-NULL-001")
    }

    "stay silent when the same check precedes the use" in {
        findingsIn("good_check_before_use") shouldBe empty
    }

    "fire on the unvalidated parameter deref at the low tier (the cwe476 chained row)" in {
        val found = findingsIn("bad_chained")
        found.map(_._1) shouldBe Set("MS-NULL-001")
        // the hypothesis arm carries its own confidence, SCOPED to its rule
        val rule = MemorySafetyFindingPass.rules(MemorySafetyFindingPass.RuleNullDeref)
        cpg.method
            .name("bad_chained")
            .ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.Expression]
            .filter(_.tag.name("ms-finding").l.nonEmpty)
            .forall(n =>
                n.tag.name("ms-confidence").value.l.contains("MS-NULL-001=low") &&
                    MemorySafetyFindingPass.confidenceOf(n, rule) == "low"
            ) shouldBe true
    }

    "fire on an unchecked strchr result" in {
        findingsIn("bad_unchecked_strchr").map(_._1) shouldBe Set("MS-NULL-001")
    }

    "stay silent when the strchr result is guarded" in {
        findingsIn("good_checked_strchr") shouldBe empty
    }

    "fire on a write through an unchecked allocation at a mem-dst position (F1)" in {
        findingsIn("bad_memcpy_unchecked").map(_._1) shouldBe Set("MS-NULL-001")
    }

    "stay silent when only the copy's length is handed unchecked (F1)" in {
        // MS-BOUND-002 may still ask its own question about the caller-controlled length
        // (the function is externally reachable); the NULL rule must not fire on it
        findingsIn("good_memcpy_checked_len") should not contain "MS-NULL-001"
    }
end NullDerefRuleTests
