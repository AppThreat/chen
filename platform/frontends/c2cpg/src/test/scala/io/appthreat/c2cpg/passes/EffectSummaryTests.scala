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
    |
    |/* F1 (part 6): derefs-param - a method that reads through a parameter on every path */
    |static int len_of(char *s)
    |{
    |    return s[0];
    |}
    |
    |/* the author guards first: no summary - the deref is NOT on every path */
    |static int first_or_zero(char *s)
    |{
    |    if (s == NULL)
    |        return 0;
    |    return s[0];
    |}
    |
    |/* a deref under a condition: no summary, CDG evidence says some path only */
    |static int cond_deref(char *s, int flag)
    |{
    |    if (flag)
    |        return s[0];
    |    return 0;
    |}
    |
    |/* one hop: the parameter is handed to a str* reader at its haystack position */
    |static int starts_with_url(const char *s)
    |{
    |    return strstr(s, "://") != NULL;
    |}
    |
    |/* hands the pointer on but nothing reads through it: no summary */
    |static void log_ptr(const char *tag, char *maybe)
    |{
    |    printf("%s %p\n", tag, (void *)maybe);
    |}
    |
    |void bad_derefing_helper(void)
    |{
    |    char *p = (char *)malloc(16);
    |    int c = len_of(p);
    |    if (p == NULL) return;
    |    (void)c;
    |    free(p);
    |}
    |
    |void good_null_tolerant_helper(void)
    |{
    |    char *p = (char *)malloc(16);
    |    log_ptr("p", p);
    |    if (p == NULL) return;
    |    free(p);
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
        // busy_freep also reads through its parameter (`*pp` loads the slot), so F1's
        // derefs-param is honestly its second effect - a NULL `char **` would crash it
        effectsOf("busy_freep") shouldBe Set("effect:frees-param:1", "effect:derefs-param:1")
        effectsOf("maybe_free") shouldBe empty
        effectsOf("busy_alloc") shouldBe Set("effect:allocates-return")
    }

    "make a double free through a busy free wrapper visible (MS-ALLOC-001)" in {
        // F1: the unchecked malloc result handed to a pure free wrapper is NOT a null-use -
        // free(NULL) is a no-op, and busy_free reads through nothing - so only the double
        // free remains
        findingsIn("bad_double_via_summary") shouldBe Set("MS-ALLOC-001")
    }

    "not report a single free through the same wrapper" in {
        findingsIn("good_freed_once_via_summary") shouldBe empty
    }

    "make a double free through a freep-style wrapper visible" in {
        // F1: `&p` hands the wrapper the SLOT, and a local's slot is never null - no null-use
        findingsIn("bad_double_via_freep_summary") shouldBe Set("MS-ALLOC-001")
    }

    "not conclude a summary from a conditional free" in {
        // maybe_free frees on SOME path; the summary vocabulary says what a call ALWAYS does
        findingsIn("good_conditional_no_summary") shouldBe empty
    }

    "conclude derefs-param for an unconditional read-through and nothing else" in {
        effectsOf("len_of") shouldBe Set("effect:derefs-param:1")
        effectsOf("first_or_zero") shouldBe empty
        effectsOf("cond_deref") shouldBe empty
        effectsOf("log_ptr") shouldBe empty
        // the hop: starts_with_url reads through its parameter only because strstr does
        effectsOf("starts_with_url") shouldBe Set("effect:derefs-param:1")
    }

    "report the null use a derefs-param summary licenses (F1)" in {
        findingsIn("bad_derefing_helper") shouldBe Set("MS-NULL-001")
    }

    "stay silent when the callee summary says the pointer is only logged (F1)" in {
        findingsIn("good_null_tolerant_helper") shouldBe empty
    }

    "track an allocation returned by a busy allocator (its leak becomes visible)" in {
        // the summary states the ALLOCATION, not the nullability: nullable is a declared
        // API fact, never inferred, so no null-deref claim rides along
        findingsIn("bad_leak_via_alloc_summary") shouldBe Set("MS-ALLOC-003")
    }
end EffectSummaryTests
