package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A self-sized destination needs EVERY value it can hold at the copy to be sized from the copy's
  * length - an allocation of it, or a buffer a dominating guard proved large enough.
  */
class SelfSizedDestinationTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |struct key { char space_[24]; char other_[4]; };
    |
    |/* the fixed buffer path overruns whenever n > 16 */
    |void mixed_fixed_malloc(const char *s, unsigned n, int c, char **out)
    |{
    |    char buf[16];
    |    char *d = buf;
    |    if (c)
    |        d = (char *)malloc(n);
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |/* every value is an allocation of at least n */
    |void both_malloc(const char *s, unsigned n, int c, char **out)
    |{
    |    char *d = (char *)malloc(n);
    |    if (c)
    |        d = (char *)malloc(n + 4);
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |/* a call handed the pointer does not change which buffer it is */
    |void through_memset(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)malloc(n);
    |    memset(d, 0, n);
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |/* the guard sizes one member, the assignment takes another */
    |void guard_other_buffer(struct key *k, const char *bytes, unsigned n)
    |{
    |    size_t need = (size_t)n + 8;
    |    char *dst;
    |    if (need <= sizeof(k->space_))
    |        dst = k->other_;
    |    else
    |        dst = new char[need];
    |    memcpy(dst, bytes, n);
    |}
    |
    |/* the guard points the wrong way: the fixed member is taken when need is LARGE */
    |void guard_wrong_way(struct key *k, const char *bytes, unsigned n)
    |{
    |    size_t need = (size_t)n + 8;
    |    char *dst;
    |    if (need >= sizeof(k->space_))
    |        dst = k->space_;
    |    else
    |        dst = new char[need];
    |    memcpy(dst, bytes, n);
    |}
    |
    |/* the correct twin: the fixed-or-heap store shape */
    |void guard_covers(struct key *k, const char *bytes, unsigned n)
    |{
    |    size_t need = (size_t)n + 8;
    |    char *dst;
    |    if (need <= sizeof(k->space_))
    |        dst = k->space_;
    |    else
    |        dst = new char[need];
    |    memcpy(dst, bytes, n);
    |}
    |
    |/* the length handed to a constructor is not the size of what `new` allocates */
    |struct Wrapper { char *data; explicit Wrapper(unsigned n); };
    |void constructor_argument_is_not_a_size(const char *bytes, unsigned n, char **out)
    |{
    |    char *dst = (char *)new Wrapper(n);
    |    memcpy(dst, bytes, n);
    |    *out = dst;
    |}
    |
    |/* the extent of an array allocation is */
    |void array_new_of_the_length(const char *bytes, unsigned n, char **out)
    |{
    |    char *dst = new char[n];
    |    memcpy(dst, bytes, n);
    |    *out = dst;
    |}
    |""".stripMargin,
    "self_sized.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains("MS-BOUND-002")).l

  "the self-sized destination" should:
    "report a copy whose destination may still be the fixed buffer" in {
        findingsIn("mixed_fixed_malloc") should not be empty
    }
    "stay silent when every value is an allocation of the length" in {
        findingsIn("both_malloc") shouldBe empty
    }
    "look through a call the pointer is handed to" in {
        findingsIn("through_memset") shouldBe empty
    }
    "report a guard that sizes a different buffer than the one assigned" in {
        findingsIn("guard_other_buffer") should not be empty
    }
    "report a guard that bounds the length from below" in {
        findingsIn("guard_wrong_way") should not be empty
    }
    "stay silent when a dominating guard proves the fixed buffer large enough" in {
        findingsIn("guard_covers") shouldBe empty
    }
    "not read a constructor argument as the size of a scalar allocation" in {
        findingsIn("constructor_argument_is_not_a_size") should not be empty
    }
    "read an array allocation's extent as its size" in {
        findingsIn("array_new_of_the_length") shouldBe empty
    }
end SelfSizedDestinationTests
