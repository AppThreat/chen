package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 11 review: shapes the three new arms must still report (off-by-one bounds, a guard whose
  * length is redefined after it) and one they must not (an out-param filled from a table, not from
  * the walked bytes).
  */
class Part11ReviewTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdint.h>
    |#include <stdio.h>
    |#include <stdlib.h>
    |#include <string.h>
    |
    |struct entry { long pos; };
    |struct fmt_ctx { unsigned int nb_streams; };
    |struct sub_ctx { struct entry q[32]; };
    |struct packet { const uint8_t *data; int data_len; };
    |
    |static void add_stream(struct fmt_ctx *ctx) { ctx->nb_streams++; }
    |static void put(struct entry *e, long pos) { e->pos = pos; }
    |
    |/* `> 32` lets 32 through: after the growth the count is 33 and q[32] is written */
    |int r1_nonstrict_exit(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        if (ctx->nb_streams > 32)
    |            return -1;
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |/* the fix's exit, but the index is the count itself: q[32] after the 32nd growth */
    |int r2_exit_before_growth_offset0(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        if (ctx->nb_streams >= 32)
    |            return -1;
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams], 1);
    |    }
    |    return 0;
    |}
    |
    |/* the loop condition admits 32 before the growth: 33, then q[32] */
    |int r3_nonstrict_loop_bound(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (ctx->nb_streams <= 32 && fgets(line, sizeof(line), idx))
    |    {
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |/* checked after the growth, non-strict: the count can be 32 at q[count] */
    |int r4_nonstrict_exit_after_growth(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        add_stream(ctx);
    |        if (ctx->nb_streams > 32)
    |            return -1;
    |        put(&sub->q[ctx->nb_streams], 1);
    |    }
    |    return 0;
    |}
    |
    |/* the correct twins: each must stay silent */
    |int g1_exit_before_growth(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        if (ctx->nb_streams >= 32)
    |            return -1;
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |int g2_exit_after_growth(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        add_stream(ctx);
    |        if (ctx->nb_streams >= 32)
    |            return -1;
    |        put(&sub->q[ctx->nb_streams], 1);
    |    }
    |    return 0;
    |}
    |
    |int g3_nonstrict_exit_before_growth(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        if (ctx->nb_streams > 31)
    |            return -1;
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |/* the guard bounds an earlier value of the length; the copy runs on a redefined one */
    |int r5_guard_then_redefined(struct packet *pkt)
    |{
    |    int pkt_size = pkt->data_len;
    |    uint8_t *dst;
    |    if (pkt_size > pkt->data_len)
    |        return -1;
    |    pkt_size = ((int)pkt->data[8] << 8) | pkt->data[9];
    |    dst = (uint8_t *)malloc(pkt_size + 4);
    |    memcpy(dst + 4, pkt->data, pkt_size);
    |    free(dst);
    |    return 0;
    |}
    |
    |int g5_guard_after_definition(struct packet *pkt)
    |{
    |    int pkt_size = ((int)pkt->data[8] << 8) | pkt->data[9];
    |    uint8_t *dst;
    |    if (pkt_size > pkt->data_len)
    |        return -1;
    |    dst = (uint8_t *)malloc(pkt_size + 4);
    |    memcpy(dst + 4, pkt->data, pkt_size);
    |    free(dst);
    |    return 0;
    |}
    |
    |/* fills out from a table, not from the bytes it is handed a pointer to */
    |static const uint32_t step_table[4] = {1, 2, 3, 4};
    |static int lookup(const uint32_t *table, int k, uint32_t *out)
    |{
    |    *out = table[k & 3];
    |    return 1;
    |}
    |
    |int g6_step_from_a_table(const uint8_t *frame, int frame_size)
    |{
    |    const uint8_t *p = frame;
    |    int rem = frame_size;
    |    while (rem > 4)
    |    {
    |        uint32_t sz;
    |        uint8_t hdr = *p;
    |        lookup(step_table, hdr, &sz);
    |        p += 1 + sz;
    |        rem -= 1 + sz;
    |    }
    |    return 0;
    |}
    |""".stripMargin,
    "part11review.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String, rules: String*): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.exists(rules.contains)).l

  private val index = Seq("MS-BOUND-003", "MS-BOUND-004")

  "the counter-indexed array arm" should:
    "report a non-strict exit that admits one growth too many" in {
        findingsIn("r1_nonstrict_exit", index*) should not be empty
    }
    "report the fix's exit when the index is the count itself" in {
        findingsIn("r2_exit_before_growth_offset0", index*) should not be empty
    }
    "report a non-strict loop bound" in {
        findingsIn("r3_nonstrict_loop_bound", index*) should not be empty
    }
    "report a non-strict exit after the growth, indexing the count" in {
        findingsIn("r4_nonstrict_exit_after_growth", index*) should not be empty
    }
    "stay silent on the exact bounds before and after the growth" in {
        findingsIn("g1_exit_before_growth", index*) shouldBe empty
        findingsIn("g2_exit_after_growth", index*) shouldBe empty
        findingsIn("g3_nonstrict_exit_before_growth", index*) shouldBe empty
    }

  "the source-overread arm" should:
    "report a length redefined after the guard that bounded it" in {
        findingsIn("r5_guard_then_redefined", "MS-BOUND-008") should not be empty
    }
    "stay silent when the guard follows the definition" in {
        findingsIn("g5_guard_after_definition", "MS-BOUND-008") shouldBe empty
    }

  "the paired-advance arm" should:
    "not treat a table lookup's out-param as bytes decoded from the walked buffer" in {
        findingsIn("g6_step_from_a_table", "MS-BOUND-003") shouldBe empty
    }
end Part11ReviewTests
