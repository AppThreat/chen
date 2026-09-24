package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Allocation state through struct fields and aliases: `s->p` is tracked as its own variable, a
  * copy of a pointer shares its block's fate, and a callee that frees a field of its argument on
  * a failure path double-frees with a caller that releases it after that failure.
  */
class FieldAliasStateTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <stdio.h>
    |struct box { char *p; void *ctx; };
    |
    |void uaf_loop(void)
    |{
    |    char *p = (char *)malloc(32);
    |    int i;
    |    if (p == NULL) return;
    |    for (i = 0; i < 3; i++) {
    |        printf("%c", p[0]);
    |        free(p);
    |    }
    |}
    |void uaf_alias(void)
    |{
    |    char *p = (char *)malloc(8);
    |    char *q;
    |    if (!p) return;
    |    q = p;
    |    free(p);
    |    q[0] = 1;
    |}
    |void ok_alias(void)
    |{
    |    char *p = (char *)malloc(8);
    |    char *q;
    |    if (!p) return;
    |    q = p;
    |    q[0] = 1;
    |    free(p);
    |}
    |void uaf_field(struct box *b)
    |{
    |    b->p = (char *)malloc(8);
    |    if (!b->p) return;
    |    free(b->p);
    |    b->p[0] = 1;
    |}
    |void df_field(struct box *b)
    |{
    |    free(b->p);
    |    free(b->p);
    |}
    |void ok_field_reset(struct box *b)
    |{
    |    free(b->p);
    |    b->p = NULL;
    |    free(b->p);
    |}
    |void ok_field_other(struct box *b, struct box *c)
    |{
    |    free(b->p);
    |    free(c->p);
    |}
    |void ok_field_rebased(struct box *b, struct box *c)
    |{
    |    free(b->p);
    |    b = c;
    |    free(b->p);
    |}
    |void ok_field_leak_is_ownership(struct box *b)
    |{
    |    b->p = (char *)malloc(8);
    |}
    |
    |/* CVE-2026-64832's shape: neither function is wrong on its own */
    |static void release_box(struct box *b) { free(b->ctx); b->ctx = NULL; }
    |static int start_bad(struct box *b, int sep)
    |{
    |    b->ctx = malloc(64);
    |    if (b->ctx == NULL) return -1;
    |    if (sep) {
    |        void *extra = malloc(32);
    |        if (extra == NULL) {
    |            free(b->ctx);
    |            return -1;
    |        }
    |        free(extra);
    |    }
    |    return 0;
    |}
    |void caller_bad(int sep)
    |{
    |    struct box b = {NULL, NULL};
    |    if (start_bad(&b, sep) < 0)
    |        release_box(&b);
    |}
    |static int start_good(struct box *b, int sep)
    |{
    |    b->ctx = malloc(64);
    |    if (b->ctx == NULL) return -1;
    |    if (sep) {
    |        void *extra = malloc(32);
    |        if (extra == NULL)
    |            return -1;
    |        free(extra);
    |    }
    |    return 0;
    |}
    |void caller_good(int sep)
    |{
    |    struct box b = {NULL, NULL};
    |    if (start_good(&b, sep) < 0)
    |        release_box(&b);
    |}
    |/* frees on failure, but its caller does not release again: correct */
    |static int start_owned(struct box *b)
    |{
    |    b->ctx = malloc(64);
    |    if (b->ctx == NULL) return -1;
    |    if (b->p == NULL) { free(b->ctx); return -1; }
    |    return 0;
    |}
    |void caller_owned(void)
    |{
    |    struct box b = {NULL, NULL};
    |    if (start_owned(&b) < 0)
    |        return;
    |    release_box(&b);
    |}
    |""".stripMargin,
    "fields.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  private def lines(method: String, rule: String): Set[Int] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(_.tag.nameExact("ms-finding").valueExact(rule).nonEmpty)
          .flatMap(_.propertiesMap.get("LINE_NUMBER") match
            case i: Integer => Some(i.toInt)
            case _          => None
          ).l.toSet

  "a loop" should:
    "carry a free into the next iteration's use" in {
        findingsIn("uaf_loop") should contain("MS-ALLOC-002")
    }

  "an alias" should:
    "share its block's free" in { findingsIn("uaf_alias") should contain("MS-ALLOC-002") }
    "not be reported when used before the free" in {
        findingsIn("ok_alias") should not contain "MS-ALLOC-002"
        findingsIn("ok_alias") should not contain "MS-ALLOC-003"
    }

  "a struct field" should:
    "be tracked for use after free and double free" in {
        findingsIn("uaf_field") should contain("MS-ALLOC-002")
        findingsIn("df_field") should contain("MS-ALLOC-001")
    }
    "not be reported after a reset, on another base, or after the base is rebound" in {
        Seq("ok_field_reset", "ok_field_other", "ok_field_rebased").foreach { m =>
            withClue(m) { findingsIn(m) should not contain "MS-ALLOC-001" }
        }
    }
    "not leak when stored into a caller's struct" in {
        findingsIn("ok_field_leak_is_ownership") should not contain "MS-ALLOC-003"
    }

  "a function freeing a member of its argument" should:
    "not be a free of the argument" in {
        val sem =
            cpg.method.nameExact("release_box").tag.nameExact(MemorySemanticsPass.TagSemantic).value.l
        sem should not contain "free:heap"
    }

  "a callee freeing a field on failure" should:
    "double free with a caller that releases it after that failure" in {
        findingsIn("start_bad") should contain("MS-ALLOC-001")
        lines("start_bad", "MS-ALLOC-001") shouldBe Set(77)
    }
    "not be reported when it keeps ownership, or its caller does not release again" in {
        findingsIn("start_good") should not contain "MS-ALLOC-001"
        findingsIn("start_owned") should not contain "MS-ALLOC-001"
        findingsIn("caller_good") should not contain "MS-ALLOC-001"
    }
end FieldAliasStateTests
