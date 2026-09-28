package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A field the method stored once, on every path, and nothing rewrote since reads as that stored
  * value - for the self-sized copy, the self-sized loop and the value range of a loop count.
  */
class FieldStoreRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |struct split { unsigned char *buf; int size; };
    |struct rm { int cnt; int lens[16]; };
    |struct st { unsigned char *adpc; };
    |struct st2 { unsigned char *adpc; };
    |void reset(struct split *d);
    |
    |void split_sized(struct split *d, const unsigned char *src, int len)
    |{
    |    d->size = len;
    |    d->buf = (unsigned char *)malloc(d->size);
    |    memcpy(d->buf, src, d->size);
    |}
    |
    |void split_fixed(struct split *d, const unsigned char *src, int len)
    |{
    |    d->size = len;
    |    d->buf = (unsigned char *)malloc(16);
    |    memcpy(d->buf, src, d->size);
    |}
    |
    |void split_rewritten(struct split *d, const unsigned char *src, int len)
    |{
    |    d->buf = (unsigned char *)malloc(len);
    |    reset(d);
    |    memcpy(d->buf, src, len);
    |}
    |
    |void masked_count(struct rm *a, int word, const int *vals)
    |{
    |    int x;
    |    a->cnt = (word & 0xf0) >> 4;
    |    for (x = 0; x < a->cnt; x++)
    |        a->lens[x] = vals[x];
    |}
    |
    |void shifted_count(struct rm *a, int word, const int *vals)
    |{
    |    int x;
    |    a->cnt = word >> 4;
    |    for (x = 0; x < a->cnt; x++)
    |        a->lens[x] = vals[x];
    |}
    |
    |void loop_over_the_allocation(struct st *b, int asize)
    |{
    |    int i;
    |    b->adpc = (unsigned char *)malloc(asize);
    |    for (i = 0; i < asize; i++)
    |        b->adpc[i] = 0;
    |}
    |
    |void loop_past_the_allocation(struct st2 *b, int asize)
    |{
    |    int i;
    |    b->adpc = (unsigned char *)malloc(16);
    |    for (i = 0; i < asize; i++)
    |        b->adpc[i] = 0;
    |}
    |""".stripMargin,
    "fieldstore.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): List[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l)
          .filter(_.startsWith("MS-BOUND")).l

  "a field stored once" should:
    "size a copy into the buffer its store allocated" in {
        findingsIn("split_sized") shouldBe empty
    }
    "not excuse a copy past a fixed-size store" in {
        findingsIn("split_fixed") should not be empty
    }
    "not be trusted once a call is handed the struct" in {
        findingsIn("split_rewritten") should not be empty
    }
    "bound a loop count by the stored value's range" in {
        findingsIn("masked_count") shouldBe empty
    }
    "not bound a loop count whose stored value can exceed the extent" in {
        findingsIn("shifted_count") should not be empty
    }
    "size a loop over the buffer its store allocated" in {
        findingsIn("loop_over_the_allocation") shouldBe empty
    }
    "not excuse a loop past a fixed-size store" in {
        findingsIn("loop_past_the_allocation") should not be empty
    }
end FieldStoreRuleTests
