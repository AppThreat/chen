package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 12 review: shapes the part 12 stand-downs must not swallow - a ternary whose condition does
  * not prove the pointer non-null on the arm it excuses, a flexible member of an allocation that
  * never added the header, and a length call whose operand changed between the allocation and the
  * copy.
  */
class Part12ReviewTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |struct node { struct node *next; int marked; };
    |struct entry { int refs; char data[1]; };
    |
    |/* the then arm runs exactly when n IS null */
    |int mixed_ternary(struct node *n, int flag)
    |{
    |    int v = (!n && flag) ? n->marked : 0;
    |    if (n == 0)
    |        return 0;
    |    return v;
    |}
    |
    |/* the then arm of an or proves nothing about n */
    |int or_ternary(struct node *n, int flag)
    |{
    |    int v = (n || flag) ? n->marked : 0;
    |    if (n == 0)
    |        return 0;
    |    return v;
    |}
    |
    |/* the correct twin: a conjunction proves every conjunct on the then arm */
    |int and_ternary(struct node *n, int flag)
    |{
    |    int v = (n && flag) ? n->marked : 0;
    |    if (n == 0)
    |        return 0;
    |    return v;
    |}
    |
    |/* the allocation is exactly n: the header before data pushes the copy n-4 bytes past it */
    |void flex_no_header(struct entry **slot, const char *bytes, unsigned n)
    |{
    |    struct entry *e = (struct entry *)malloc(n);
    |    memcpy(e->data, bytes, n);
    |    *slot = e;
    |}
    |
    |/* same spelling, different value: src changed between the allocation and the copy */
    |void strlen_changed(char **out, const char *a, const char *b)
    |{
    |    const char *src = a;
    |    char *d = (char *)malloc(strlen(src));
    |    src = b;
    |    memcpy(d, src, strlen(src));
    |    *out = d;
    |}
    |
    |/* the correct twin: the same call on the same value */
    |void strlen_same(char **out, const char *a)
    |{
    |    const char *src = a;
    |    char *d = (char *)malloc(strlen(src));
    |    memcpy(d, src, strlen(src));
    |    *out = d;
    |}
    |""".stripMargin,
    "part12review.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String, rule: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains(rule)).l

  "the ternary narrowing" should:
    "not excuse the then arm of a conjunction with a negated conjunct" in {
        findingsIn("mixed_ternary", "MS-NULL-001") should not be empty
    }
    "not excuse the then arm of a disjunction" in {
        findingsIn("or_ternary", "MS-NULL-001") should not be empty
    }
    "excuse the then arm of a conjunction of positive tests" in {
        findingsIn("and_ternary", "MS-NULL-001") shouldBe empty
    }

  "the self-sized destination" should:
    "not excuse a flexible member of an allocation that never added the header" in {
        findingsIn("flex_no_header", "MS-BOUND-002") should not be empty
    }
    "not match a length call whose operand was redefined" in {
        findingsIn("strlen_changed", "MS-BOUND-002") should not be empty
    }
    "match the same length call on the same value" in {
        findingsIn("strlen_same", "MS-BOUND-002") shouldBe empty
    }
end Part12ReviewTests
