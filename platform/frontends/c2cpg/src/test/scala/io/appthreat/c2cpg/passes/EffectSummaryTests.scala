package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    MemoryApiPass,
    MemorySafetyFindingPass
}
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*

/** E5 (part 5): per-method effect summaries. A method that unconditionally frees one of its
  * parameters carries `effect:frees-param:<i>` on its METHOD node, and every call to it frees the
  * matching argument at the caller - an interprocedural free as a tag lookup, read by the existing
  * MS-ALLOC-001 without becoming interprocedural itself.
  *
  * The wrappers here are deliberately NOT pure: the C2 body-shape inference only concludes wrappers
  * whose external calls are frees alone, so these summaries are the half it cannot see.
  */
class EffectSummaryTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <stdio.h>
    |
    |/* a busy free wrapper: the log call beside the free is what the body-shape inference
    |   declines - the summary must not */
    |static void busy_free(void *p)
    |{
    |    printf("freeing %p\n", p);
    |    free(p);
    |}
    |
    |/* a freep-style wrapper: takes the address, so the CALLER's variable is freed (and the
    |   caller's copy is left dangling, not nulled) */
    |static void busy_freep(void **p)
    |{
    |    printf("freeing %p\n", *p);
    |    free(*p);
    |}
    |
    |/* a CONDITIONAL free: no summary - a "always frees" summary here would turn every
    |   call followed by a real free into a false double free */
    |static void maybe_free(void *p, int c)
    |{
    |    printf("maybe\n");
    |    if (c)
    |        free(p);
    |}
    |
    |void bad_double_via_summary(void)
    |{
    |    char *p = (char *)malloc(16);
    |    busy_free(p);
    |    busy_free(p);
    |}
    |
    |void good_freed_once_via_summary(void)
    |{
    |    char *p = (char *)malloc(16);
    |    busy_free(p);
    |}
    |
    |void bad_double_via_freep_summary(int n)
    |{
    |    char *p = (char *)malloc(16);
    |    busy_freep(&p);
    |    busy_freep(&p);
    |}
    |
    |void good_conditional_no_summary(void)
    |{
    |    char *p = (char *)malloc(16);
    |    maybe_free(p, 1);
    |    free(p);
    |}
    |
    |/* allocates-return: a busy allocator whose body is more than the allocation */
    |static char *busy_alloc(size_t n)
    |{
    |    char *p = (char *)malloc(n);
    |    printf("allocating %zu\n", n);
    |    return p;
    |}
    |
    |void bad_leak_via_alloc_summary(void)
    |{
    |    char *q = busy_alloc(32);
    |    q[0] = 'x';
    |}
    |""".stripMargin,
    "effects.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet

  private def effectsOf(method: String): Set[String] =
      cpg.method
          .name(method)
          .flatMap(_.tag.name(AllocationStatePass.TagEffect).value.l)
          .l
          .toSet

  "effect summaries" should:

    "land the facts on the method node" in {
        effectsOf("busy_free") shouldBe Set("effect:frees-param:1")
        effectsOf("busy_freep") shouldBe Set("effect:frees-param:1")
        effectsOf("maybe_free") shouldBe empty
        effectsOf("busy_alloc") shouldBe Set("effect:allocates-return")
    }

    "make a double free through a busy free wrapper visible (MS-ALLOC-001)" in {
        // the unchecked malloc result handed to the wrapper also draws MS-NULL-001's call-arg
        // arm - a genuine "may be null when read" claim about the same statement
        findingsIn("bad_double_via_summary") shouldBe Set("MS-ALLOC-001", "MS-NULL-001")
    }

    "not report a single free through the same wrapper" in {
        findingsIn("good_freed_once_via_summary") shouldBe Set("MS-NULL-001")
    }

    "make a double free through a freep-style wrapper visible" in {
        findingsIn("bad_double_via_freep_summary") shouldBe Set("MS-ALLOC-001", "MS-NULL-001")
    }

    "not conclude a summary from a conditional free" in {
        // maybe_free frees on SOME path; the summary vocabulary says what a call ALWAYS does.
        // The MS-NULL-001 hit is arm 1's honest claim about the same statement (an unchecked
        // allocation result handed to a call) - not a double-free claim
        findingsIn("good_conditional_no_summary") shouldBe Set("MS-NULL-001")
    }

    "track an allocation returned by a busy allocator (its leak becomes visible)" in {
        findingsIn("bad_leak_via_alloc_summary") shouldBe Set("MS-ALLOC-003", "MS-NULL-001")
    }
end EffectSummaryTests
