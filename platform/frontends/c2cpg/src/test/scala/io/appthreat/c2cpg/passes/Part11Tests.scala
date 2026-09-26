package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 11: the three recall arms - the counter-indexed array (CVE-2026-64830), the source overread
  * of a copy (CVE-2026-64833) and the advance by a decoded size (CVE-2026-75147) - with the
  * negative shapes each task names. Every stand-down here fails (fires) on the part 10 base except
  * where a note says the base already over-fired there.
  */
class Part11CounterIndexTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdio.h>
    |
    |#define ARRAY_ELEMS(a) (sizeof(a) / sizeof((a)[0]))
    |
    |struct entry { long pos; };
    |struct fmt_ctx { unsigned int nb_streams; };
    |struct sub_ctx { struct entry q[32]; };
    |
    |/* the library boundary: the definition of the count is inside the callee */
    |static void add_stream(struct fmt_ctx *ctx)
    |{
    |    ctx->nb_streams++;
    |}
    |
    |/* options.c's own shape: the increment embedded in an indexAccess store */
    |static void *grower_embedded(struct fmt_ctx *ctx, void *st, void **streams)
    |{
    |    streams[ctx->nb_streams++] = st;
    |    return st;
    |}
    |
    |static void put(struct entry *e, long pos)
    |{
    |    e->pos = pos;
    |}
    |
    |int bad_counter_index(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |int good_exit_bounds_count(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        if (ctx->nb_streams >= ARRAY_ELEMS(sub->q))
    |            return -1;
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |int good_exit_bounds_count_literal(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
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
    |int good_exit_bounds_count_too_late(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        if (ctx->nb_streams >= 64)
    |            return -1; /* the bound admits indices past the 32-entry array */
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |int good_guard_names_another_field(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx,
    |                                   unsigned int other)
    |{
    |    char line[256];
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        if (other >= ARRAY_ELEMS(sub->q))
    |            return -1; /* bounds other, not the count: the vulnerable tree's own red herring */
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |int good_loop_bound_is_the_count(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    while (ctx->nb_streams < 16 && fgets(line, sizeof(line), idx))
    |    {
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |int good_count_bumped_once(struct sub_ctx *sub, struct fmt_ctx *ctx)
    |{
    |    add_stream(ctx);
    |    put(&sub->q[ctx->nb_streams - 1], 1);
    |    return 0;
    |}
    |
    |int bad_guard_outside_the_loop(struct sub_ctx *sub, struct fmt_ctx *ctx, FILE *idx)
    |{
    |    char line[256];
    |    if (ctx->nb_streams >= 32)
    |        return -1; /* checked once: the loop adds one per line afterwards */
    |    while (fgets(line, sizeof(line), idx))
    |    {
    |        add_stream(ctx);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |
    |int bad_grown_via_embedded_shape(struct sub_ctx *sub, struct fmt_ctx *ctx, void **streams,
    |                                  void *st, int n)
    |{
    |    int i;
    |    for (i = 0; i < n; i++)
    |    {
    |        grower_embedded(ctx, st, streams);
    |        put(&sub->q[ctx->nb_streams - 1], 1);
    |    }
    |    return 0;
    |}
    |""".stripMargin,
    "part11counter.c"
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

  "the counter-indexed array arm" should:
    "report a count grown by a callee inside a loop, indexed into a fixed array" in {
        findingsIn("bad_counter_index", "MS-BOUND-004") should not be empty
    }

    "stand down on a dominating exit that names the array's element count" in {
        findingsIn("good_exit_bounds_count", "MS-BOUND-004") shouldBe empty
        findingsIn("good_exit_bounds_count", "MS-BOUND-003") shouldBe empty
    }

    "stand down on a dominating exit with the capacity as a literal" in {
        findingsIn("good_exit_bounds_count_literal", "MS-BOUND-004") shouldBe empty
    }

    "not stand down when the exit's bound admits indices past the capacity" in {
        findingsIn("good_exit_bounds_count_too_late", "MS-BOUND-004") should not be empty
    }

    "not stand down on a guard that bounds a different field" in {
        findingsIn("good_guard_names_another_field", "MS-BOUND-004") should not be empty
    }

    "stand down when the loop's own condition bounds the count" in {
        findingsIn("good_loop_bound_is_the_count", "MS-BOUND-004") shouldBe empty
    }

    "stand down on a count bumped once outside any loop" in {
        findingsIn("good_count_bumped_once", "MS-BOUND-004") shouldBe empty
        findingsIn("good_count_bumped_once", "MS-BOUND-003") shouldBe empty
    }

    "not stand down on a guard evaluated once outside the loop" in {
        findingsIn("bad_guard_outside_the_loop", "MS-BOUND-004") should not be empty
    }

    "see the increment embedded in a[p->count++] = v (options.c's shape)" in {
        findingsIn("bad_grown_via_embedded_shape", "MS-BOUND-004") should not be empty
    }
end Part11CounterIndexTests

/** The source-overread arm: MS-BOUND-008 on the definition that replaces the extent-derived length,
  * silent on the guarded and extent-derived shapes. The config-declared AVPacket pair is exercised
  * with the same JSON the corpus passes.
  */
class Part11SourceOverreadTests extends DataFlowCodeToCpgSuite:

  private val pairConfig =
      """{"apis": [], "bufferExtents": [{"type": "packet", "buffer": "data", "capacity": "size"}]}"""

  private val cpg = code(
    """
    |#include <stdint.h>
    |#include <stdio.h>
    |#include <stdlib.h>
    |#include <string.h>
    |
    |#define READ_BE24(p) ((uint32_t)(p)[0] << 16 | (uint32_t)(p)[1] << 8 | (uint32_t)(p)[2])
    |
    |struct packet {
    |    const uint8_t *data;
    |    int data_len;
    |};
    |
    |int bad_len_from_source_bytes(struct packet *pkt)
    |{
    |    int core = ((((uint32_t)pkt->data[5] << 16 | (uint32_t)pkt->data[6] << 8 | (uint32_t)pkt->data[7]) >> 4) & 0x3fff) + 1;
    |    int pkt_size = pkt->data_len;
    |    uint8_t *dst;
    |    if (core & 1)
    |        pkt_size = core;
    |    dst = (uint8_t *)malloc(pkt_size + 4);
    |    memcpy(dst + 4, pkt->data, pkt_size);
    |    free(dst);
    |    return 0;
    |}
    |
    |int good_guard_against_sibling(struct packet *pkt)
    |{
    |    int core = ((((uint32_t)pkt->data[5] << 16 | (uint32_t)pkt->data[6] << 8 | (uint32_t)pkt->data[7]) >> 4) & 0x3fff) + 1;
    |    int pkt_size = pkt->data_len;
    |    uint8_t *dst;
    |    if (core <= pkt->data_len)
    |        pkt_size = core;
    |    dst = (uint8_t *)malloc(pkt_size + 4);
    |    memcpy(dst + 4, pkt->data, pkt_size);
    |    free(dst);
    |    return 0;
    |}
    |
    |int good_len_derived_from_extent(struct packet *pkt)
    |{
    |    int pkt_size = pkt->data_len - 4;
    |    uint8_t *dst;
    |    if (pkt_size > 0)
    |    {
    |        dst = (uint8_t *)malloc(pkt_size + 4);
    |        memcpy(dst + 4, pkt->data, pkt_size);
    |        free(dst);
    |    }
    |    return 0;
    |}
    |
    |int good_source_known_large(FILE *f)
    |{
    |    uint8_t big[16384];
    |    uint8_t *dst;
    |    int byte;
    |    if (fread(big, 1, 8, f) != 8)
    |        return -1;
    |    int core = ((((uint32_t)big[5] << 16 | (uint32_t)big[6] << 8 | (uint32_t)big[7]) >> 4) & 0x3fff) + 1;
    |    dst = (uint8_t *)malloc(core + 4);
    |    memcpy(dst + 4, big, core);
    |    byte = dst[0];
    |    free(dst);
    |    return byte;
    |}
    |""".stripMargin,
    "part11src.c"
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

  "the source-overread arm" should:
    "report a length decoded from the source's own bytes" in {
        findingsIn("bad_len_from_source_bytes", "MS-BOUND-008") should not be empty
    }

    "stand down when a guard relates the length to the sibling extent member" in {
        findingsIn("good_guard_against_sibling", "MS-BOUND-008") shouldBe empty
    }

    "stand down when the length is derived from the extent itself" in {
        findingsIn("good_len_derived_from_extent", "MS-BOUND-008") shouldBe empty
    }

    "stand down when the source is known to hold the length's whole range" in {
        findingsIn("good_source_known_large", "MS-BOUND-008") shouldBe empty
    }
end Part11SourceOverreadTests

/** The declared (buffer, capacity) pair route: the struct's size member is NOT an in-file `_len`
  * sibling, so only the config's pair names the extent - CVE-2026-64833's own route, where
  * AVPacket's definition is outside libavformat and its data/size pair is declared.
  */
class Part11ConfigPairTests extends DataFlowCodeToCpgSuite:

  private val pairConfig =
      """{"apis": [], "bufferExtents": [{"type": "packet", "buffer": "data", "capacity": "size"}]}"""

  private val cpg = code(
    """
    |#include <stdint.h>
    |#include <stdlib.h>
    |#include <string.h>
    |
    |#define READ_BE24(p) ((uint32_t)(p)[0] << 16 | (uint32_t)(p)[1] << 8 | (uint32_t)(p)[2])
    |
    |struct packet {
    |    const uint8_t *data; /* the config names size as this member's extent */
    |    int size;
    |};
    |
    |/* spdif_header_dts4's shape: the copy sits in a helper whose length is a caller
    | * parameter, and the caller decodes it from the packet's own bytes */
    |static int emit_hd(struct packet *pkt, int core_size)
    |{
    |    int pkt_size = pkt->size;
    |    uint8_t *dst;
    |    pkt_size = core_size;
    |    dst = (uint8_t *)malloc(pkt_size + 4);
    |    memcpy(dst + 4, pkt->data, pkt_size);
    |    free(dst);
    |    return 0;
    |}
    |
    |int bad_pair_len_from_source_bytes(struct packet *pkt)
    |{
    |    int core = ((((uint32_t)pkt->data[5] << 16 | (uint32_t)pkt->data[6] << 8 | (uint32_t)pkt->data[7]) >> 4) & 0x3fff) + 1;
    |    return emit_hd(pkt, core);
    |}
    |
    |int good_pair_guard_against_capacity(struct packet *pkt)
    |{
    |    int core = ((((uint32_t)pkt->data[5] << 16 | (uint32_t)pkt->data[6] << 8 | (uint32_t)pkt->data[7]) >> 4) & 0x3fff) + 1;
    |    int pkt_size = pkt->size;
    |    uint8_t *dst;
    |    if (core <= pkt->size)
    |        pkt_size = core;
    |    dst = (uint8_t *)malloc(pkt_size + 4);
    |    memcpy(dst + 4, pkt->data, pkt_size);
    |    free(dst);
    |    return 0;
    |}
    |""".stripMargin,
    "part11pair.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg, Some(pairConfig)).createAndApply()

  private def findingsIn(method: String, rule: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains(rule)).l

  "the config-declared buffer extent pair" should:
    "decode from the config document" in {
        MemApiVocab.bufferExtents(Some(pairConfig)).get("packet") shouldBe Some(("data", "size"))
    }

    "report a decoded length against a paired-extent source" in {
        findingsIn("emit_hd", "MS-BOUND-008") should not be empty
    }

    "stand down when a guard relates the length to the paired capacity member" in {
        findingsIn("good_pair_guard_against_capacity", "MS-BOUND-008") shouldBe empty
    }
end Part11ConfigPairTests

/** The advance-by-decoded-size arm and its guards, plus the part 10 exemption it adds. */
class Part11PairedAdvanceTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdint.h>
    |
    |/* reads bytes out of buf and stores the decoded value through out */
    |static int parse_leb(const uint8_t *buf, int buf_size, uint32_t *out)
    |{
    |    uint32_t v = 0;
    |    int i = 0;
    |    while (i < buf_size && i < 8)
    |    {
    |        uint8_t b = buf[i];
    |        v |= (uint32_t)(b & 0x7f) << (7 * i);
    |        i++;
    |        if (!(b & 0x80))
    |        {
    |            *out = v;
    |            return i;
    |        }
    |    }
    |    return 0;
    |}
    |
    |int bad_advance_by_decoded_size(const uint8_t *frame, int frame_size)
    |{
    |    const uint8_t *p = frame;
    |    int rem = frame_size;
    |    while (rem > 0)
    |    {
    |        uint32_t sz;
    |        int n;
    |        uint8_t hdr = *p++;
    |        (void)hdr;
    |        rem--;
    |        n = parse_leb(p, rem, &sz);
    |        if (!n)
    |            break;
    |        p += n + sz;
    |        rem -= n + sz;
    |    }
    |    return 0;
    |}
    |
    |int good_advance_guarded_unsigned(const uint8_t *frame, int frame_size)
    |{
    |    const uint8_t *p = frame;
    |    int rem = frame_size;
    |    while (rem > 0)
    |    {
    |        uint32_t sz;
    |        int n;
    |        uint8_t hdr = *p++;
    |        (void)hdr;
    |        rem--;
    |        n = parse_leb(p, rem, &sz);
    |        if (!n)
    |            break;
    |        if (sz > (uint32_t)rem)
    |            break;
    |        p += n + sz;
    |        rem -= n + sz;
    |    }
    |    return 0;
    |}
    |
    |int good_advance_guarded_signed_spelling(const uint8_t *frame, int frame_size)
    |{
    |    const uint8_t *p = frame;
    |    int rem = frame_size;
    |    while (rem > 0)
    |    {
    |        uint32_t sz;
    |        int n;
    |        uint8_t hdr = *p++;
    |        (void)hdr;
    |        rem--;
    |        n = parse_leb(p, rem, &sz);
    |        if (!n)
    |            break;
    |        if ((long)sz > (long)rem)
    |            break;
    |        p += n + sz;
    |        rem -= n + sz;
    |    }
    |    return 0;
    |}
    |
    |int good_advance_split_after_guard(const uint8_t *frame, int frame_size)
    |{
    |    const uint8_t *p = frame;
    |    int rem = frame_size;
    |    while (rem > 0)
    |    {
    |        uint32_t sz;
    |        int n;
    |        uint8_t hdr = *p++;
    |        (void)hdr;
    |        rem--;
    |        n = parse_leb(p, rem, &sz);
    |        if (!n)
    |            break;
    |        p += n;
    |        rem -= n;
    |        if (sz > (uint32_t)rem)
    |            break;
    |        p += sz;
    |        rem -= sz;
    |    }
    |    return 0;
    |}
    |
    |int good_small_constant_step(const uint8_t *frame, int frame_size)
    |{
    |    const uint8_t *p = frame;
    |    int rem = frame_size;
    |    while (rem > 4)
    |    {
    |        uint32_t sz = (uint32_t)p[0] & 3;
    |        p += 1 + sz;
    |        rem -= 1 + sz;
    |    }
    |    return 0;
    |}
    |
    |int good_ac4dec_shape(const uint8_t *buf0, int left0)
    |{
    |    const uint8_t *buf = buf0;
    |    int left = left0;
    |    while (left > 7)
    |    {
    |        int size;
    |        if (buf[0] == 0xAC)
    |        {
    |            size = (buf[2] << 8) | buf[3];
    |            size += 4;
    |            if (left < size)
    |                break;
    |            left -= size;
    |            buf += size;
    |        }
    |        else
    |        {
    |            break;
    |        }
    |    }
    |    return 0;
    |}
    |
    |int bad_advance_by_bytes_read_inline(const uint8_t *frame, int frame_size)
    |{
    |    const uint8_t *p = frame;
    |    int rem = frame_size;
    |    while (rem > 0)
    |    {
    |        uint32_t sz = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
    |        uint8_t hdr = *p;
    |        (void)hdr;
    |        p += 2 + sz;
    |        rem -= 2 + sz;
    |    }
    |    return 0;
    |}
    |""".stripMargin,
    "part11advance.c"
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

  "the paired-advance arm" should:
    "report a walk advanced by an out-param decoded size with no bound" in {
        findingsIn("bad_advance_by_decoded_size", "MS-BOUND-003") should not be empty
    }

    "stand down on the fixed tree's unsigned guard" in {
        findingsIn("good_advance_guarded_unsigned", "MS-BOUND-003") shouldBe empty
    }

    "stand down on the fixed tree's split shape (the num_lebs half carries no decoded term)" in {
        findingsIn("good_advance_split_after_guard", "MS-BOUND-003") shouldBe empty
    }

    "stand down on an exact signed compare of two signed operands (size <= left)" in {
        findingsIn("good_advance_guarded_signed_spelling", "MS-BOUND-003") shouldBe empty
    }

    "stand down on `if (left < size) break` (ac4dec's exact shape)" in {
        findingsIn("good_ac4dec_shape", "MS-BOUND-003") shouldBe empty
    }

    "stand down on a step whose whole range fits the loop's minimum remainder" in {
        /* this one FAILS on the base: the part 10 arm fires on it today */
        findingsIn("good_small_constant_step", "MS-BOUND-003") shouldBe empty
    }

    "report a walk advanced by bytes read through the pointer itself" in {
        findingsIn("bad_advance_by_bytes_read_inline", "MS-BOUND-003") should not be empty
    }
end Part11PairedAdvanceTests

/** The MemorySemanticsPass conclusions the arms turn on: the out-param fill and the counter growth,
  * inferred from bodies the way options.c and rtp_av1.h are.
  */
class Part11SummaryTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdint.h>
    |
    |static unsigned int parse_leb(const uint8_t *buf_ptr, uint32_t buffer_size, uint32_t *obu_size)
    |{
    |    uint8_t leb128;
    |    unsigned int num_lebs = 0;
    |    *obu_size = 0;
    |    do
    |    {
    |        uint32_t leb7;
    |        if (!buffer_size)
    |            return 0;
    |        leb128 = *buf_ptr++;
    |        leb7 = leb128 & 0x7f;
    |        buffer_size--;
    |        if (num_lebs <= 4)
    |            *obu_size |= leb7 << (7 * num_lebs);
    |        num_lebs++;
    |    } while (leb128 & 0x80);
    |    return num_lebs;
    |}
    |
    |struct fmt { unsigned int nb_streams; void **streams; };
    |
    |static void *new_stream(struct fmt *s, void *st)
    |{
    |    s->streams[s->nb_streams++] = st;
    |    return st;
    |}
    |""".stripMargin,
    "part11summaries.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()

  private def valuesOf(name: String): Set[String] =
      cpg.method.nameExact(name).tag.name(MemorySemanticsPass.TagSemantic).value.l.toSet

  "the body summaries" should:
    "fill the out-param of a reader with the bytes it read (untrusted-read:3)" in {
        valuesOf("parse_leb") should contain("untrusted-read:3")
    }

    "grow the caller's counter (grow:1:nb_streams) from the embedded increment" in {
        valuesOf("new_stream") should contain("grow:1:nb_streams")
    }
end Part11SummaryTests


/** The vividas decode_block shape as the tree run hit it: the length is a parameter copied to
  * a local and narrowed by compound assignments and masks before the copy out of a 4-byte
  * local array.
  */
class Part11VividasShapeTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdint.h>
    |#include <string.h>
    |
    |static void xor_block(uint8_t *dst, const uint8_t *src, unsigned length)
    |{
    |    unsigned i;
    |    for (i = 0; i < length; i++)
    |        dst[i] ^= src[i];
    |}
    |
    |static void decode_block(uint8_t *src, uint8_t *dest, unsigned size)
    |{
    |    unsigned s = size;
    |    char tmp[4];
    |    int a2;
    |
    |    int align = 0;
    |    if (!size)
    |        return;
    |    a2 = (4 - align) & 3;
    |    if (a2 > s)
    |        a2 = s;
    |    memcpy(tmp + align, src, a2);
    |    xor_block(tmp + align, tmp + align, 4);
    |    memcpy(dest, tmp + align, a2);
    |    s -= a2;
    |
    |    if (s >= 4)
    |    {
    |        xor_block(src + a2, dest + a2, s & ~3u);
    |        s &= 3;
    |    }
    |    if (s)
    |    {
    |        size -= s;
    |        memcpy(tmp, src + size, s);
    |        xor_block(tmp, tmp, 4);
    |        memcpy(dest + size, tmp, s);
    |    }
    |}
    |""".stripMargin,
    "vividas.c"
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

  "the source-overread arm on narrowed lengths" should:
    "stay silent when the length is masked down before the copy out of the small buffer" in {
        findingsIn("decode_block", "MS-BOUND-008") shouldBe empty
    }
end Part11VividasShapeTests


/** The dashdec/hls shape: copy_size = FFMIN(extent - offset, buf_size) out of the paired
  * buffer, with FFMIN arriving from the external config the way the corpus passes it.
  */
class Part11FfminShapeTests extends DataFlowCodeToCpgSuite:

  private val config =
    """{"apis": [{"name": "FFMIN", "clamp": "min"}]}"""

  private val cpg = code(
    """
    |#include <stdint.h>
    |#include <string.h>
    |
    |struct playlist {
    |    uint8_t *init_sec_buf;
    |    unsigned int init_sec_buf_size;
    |    unsigned int init_sec_data_len;
    |    unsigned int init_sec_buf_read_offset;
    |};
    |
    |int read_data(struct playlist *v, unsigned char *buf, int buf_size)
    |{
    |    int copy_size;
    |    if (v->init_sec_buf_read_offset < v->init_sec_data_len) {
    |        copy_size = FFMIN(v->init_sec_data_len - v->init_sec_buf_read_offset, buf_size);
    |        memcpy(buf, v->init_sec_buf, copy_size);
    |        v->init_sec_buf_read_offset += copy_size;
    |        return copy_size;
    |    }
    |    return 0;
    |}
    |""".stripMargin,
    "hls.c"
  )

  new MemorySemanticsPass(cpg, Some(config)).createAndApply()
  new MemoryApiPass(cpg, Some(config)).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg, Some(config)).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg, Some(config)).createAndApply()

  private def findingsIn(method: String, rule: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains(rule)).l

  "the source-overread arm on clamped lengths" should:
    "stay silent on FFMIN(extent - offset, buf_size) out of the paired buffer" in {
        findingsIn("read_data", "MS-BOUND-008") shouldBe empty
    }
end Part11FfminShapeTests
