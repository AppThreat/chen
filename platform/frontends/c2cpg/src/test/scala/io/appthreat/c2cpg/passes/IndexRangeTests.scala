package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** MS-BOUND-003/004 index ranges: an index bounded by construction (the width of the read that made
  * it, a mask, its type) or by every caller is not an attacker index. Each negative is an idiom
  * from libavformat; the positives are the shapes that must keep firing.
  */
class IndexRangeTests extends DataFlowCodeToCpgSuite:

  import IndexRangeTests.ReaderConfig

  private val cpg = code(
    """
    |typedef struct AVIOContext AVIOContext;
    |int avio_r8(AVIOContext *pb);
    |unsigned int avio_rb32(AVIOContext *pb);
    |void use_ptr(void *p);
    |
    |struct frame_code { int flags; };
    |struct nut { struct frame_code frame_code[256]; void *extradata[4]; void *pids[8192];
    |             void *st[4]; void *ch[4][256]; };
    |
    |/* nutdec.c: the frame code is a byte - it cannot reach 256 */
    |static int decode_frame_header(struct nut *nut, int frame_code)
    |{
    |    return nut->frame_code[frame_code].flags;
    |}
    |int read_packet(struct nut *nut, AVIOContext *bc)
    |{
    |    int frame_code = avio_r8(bc);
    |    return decode_frame_header(nut, frame_code);
    |}
    |
    |/* flvdec.c's multitrack bug: a byte CAN reach past four slots */
    |static void set_extradata(struct nut *nut, int stream)
    |{
    |    use_ptr(nut->extradata[stream]);
    |}
    |void parse_multitrack(struct nut *nut, AVIOContext *pb)
    |{
    |    set_extradata(nut, avio_r8(pb));
    |}
    |
    |/* flvdec.c exactly: the byte arrives through a struct field and a conditional */
    |struct flv_ctx { AVIOContext *pb; };
    |static void queue_extradata(struct nut *nut, int stream)
    |{
    |    use_ptr(nut->extradata[stream]);
    |}
    |void read_flv_packet(struct nut *nut, struct flv_ctx *s, int multitrack)
    |{
    |    unsigned char track_idx = 0;
    |    int stream_type = -1;
    |    if (multitrack)
    |        track_idx = avio_r8(s->pb);
    |    else
    |        stream_type = 1;
    |    queue_extradata(nut, multitrack ? track_idx : stream_type);
    |}
    |
    |/* usmdec.c: a byte into the 256-wide inner dimension */
    |static void pick_channel(struct nut *nut, int ch_type, int stream_index)
    |{
    |    use_ptr(nut->ch[3][stream_index]);
    |}
    |void parse_chunk(struct nut *nut, AVIOContext *pb)
    |{
    |    pick_channel(nut, 3, avio_r8(pb));
    |}
    |
    |/* mpegts.c: the pid is masked to 13 bits where it is extracted */
    |static void set_es_id(struct nut *nut, int pid)
    |{
    |    use_ptr(nut->pids[pid]);
    |}
    |void parse_section(struct nut *nut, const unsigned char *p)
    |{
    |    set_es_id(nut, ((p[0] << 8) | p[1]) & 0x1fff);
    |}
    |
    |/* mpegts.c: the bound sits in the access's own expression (unsigned: no lower side) */
    |int add_pid_filter(struct nut *nut, unsigned int pid)
    |{
    |    if (pid >= 8192 || nut->pids[pid])
    |        return -1;
    |    return 0;
    |}
    |
    |/* asfdec_o.c / dvenc.c: every caller passes a loop counter, directly or two frames up */
    |static void deinterleave(struct nut *nut, int st_num)
    |{
    |    use_ptr(nut->st[st_num]);
    |}
    |static void inject(struct nut *nut, int channel)
    |{
    |    deinterleave(nut, channel);
    |}
    |void write_packet(struct nut *nut)
    |{
    |    int i;
    |    for (i = 0; i < 4; i++)
    |        inject(nut, i);
    |}
    |
    |/* hevc.c's shape: the caller's counter is declared in the for init and checked against a
    |   non-constant limit; the callee takes it unsigned */
    |static void add_nal(struct nut *nut, unsigned idx) { use_ptr(nut->st[idx]); }
    |void parse_nal(struct nut *nut, int type, const unsigned char *types, int n_arrays)
    |{
    |    for (unsigned i = 0; i < n_arrays; i++) {
    |        if (type == types[i])
    |            add_nal(nut, i);
    |    }
    |}
    |
    |/* the caller guards a struct's field, copies it into a local, and hands the local to the
    |       helper that indexes with it: the guard bounds the value the helper receives */
    |struct conn_state { int space; };
    |static void take_guarded_copy(struct nut *nut, int space) { use_ptr(nut->st[space]); }
    |void guarded_copy(struct nut *nut, struct conn_state *p)
    |{
    |    unsigned int space;
    |    if (p->space >= 4)
    |        return;
    |    space = p->space;
    |    take_guarded_copy(nut, space);
    |}
    |/* the copy without the guard: the helper's index is unbounded */
    |static void take_unguarded_copy(struct nut *nut, int space) { use_ptr(nut->st[space]); }
    |void unguarded_copy(struct nut *nut, struct conn_state *p)
    |{
    |    unsigned int space = p->space;
    |    take_unguarded_copy(nut, space);
    |}
    |/* the base is re-stored between the guard and the call: the guard's value is gone */
    |static void take_copy_base_written(struct nut *nut, int space) { use_ptr(nut->st[space]); }
    |void copy_base_written(struct nut *nut, struct conn_state *p, struct conn_state *other)
    |{
    |    unsigned int space;
    |    if (p->space >= 4)
    |        return;
    |    space = p->space;
    |    p = other;
    |    take_copy_base_written(nut, space);
    |}
    |/* the path is written through another pointer that may hold the same object */
    |static void take_copy_alias_written(struct nut *nut, int space) { use_ptr(nut->st[space]); }
    |void copy_alias_written(struct nut *nut, struct conn_state *p, struct conn_state *q)
    |{
    |    unsigned int space;
    |    if (p->space >= 4)
    |        return;
    |    q->space = 9;
    |    space = p->space;
    |    take_copy_alias_written(nut, space);
    |}
    |/* a call between the guard and the copy can write the path: it is handed the path's address,
    |   or the object is reachable without it */
    |void read_space(int *out);
    |void refresh_state(void);
    |static void take_copy_address_passed(struct nut *nut, int space) { use_ptr(nut->st[space]); }
    |void copy_address_passed(struct nut *nut, struct conn_state *p)
    |{
    |    unsigned int space;
    |    if (p->space >= 4)
    |        return;
    |    read_space(&p->space);
    |    space = p->space;
    |    take_copy_address_passed(nut, space);
    |}
    |static void take_copy_after_call(struct nut *nut, int space) { use_ptr(nut->st[space]); }
    |void copy_after_call(struct nut *nut, struct conn_state *p)
    |{
    |    unsigned int space;
    |    if (p->space >= 4)
    |        return;
    |    refresh_state();
    |    space = p->space;
    |    take_copy_after_call(nut, space);
    |}
    |/* the path is incremented between the guard and the copy */
    |static void take_copy_incremented(struct nut *nut, int space) { use_ptr(nut->st[space]); }
    |void copy_incremented(struct nut *nut, struct conn_state *p)
    |{
    |    unsigned int space;
    |    if (p->space >= 4)
    |        return;
    |    p->space++;
    |    space = p->space;
    |    take_copy_incremented(nut, space);
    |}
    |
    |/* tiertexseq.c's shape: checked above in the helper; the caller passes a byte element, which
    |   stays non-negative in the helper's int */
    |struct seq { void *frame_buffers[30]; };
    |static int fill_buffer(struct seq *seq, int buffer_num)
    |{
    |    if (buffer_num >= 30)
    |        return -1;
    |    use_ptr(seq->frame_buffers[buffer_num]);
    |    return 0;
    |}
    |int parse_frame(struct seq *seq, AVIOContext *pb)
    |{
    |    unsigned char buffer_num[4];
    |    int i;
    |    for (i = 0; i < 4; i++)
    |        buffer_num[i] = avio_r8(pb);
    |    return fill_buffer(seq, buffer_num[1]);
    |}
    |/* ... and an unsigned int element, which can arrive negative there (the one-sided shape) */
    |static int fill_wide(struct seq *seq, int buffer_num)
    |{
    |    if (buffer_num >= 30)
    |        return -1;
    |    use_ptr(seq->frame_buffers[buffer_num]);
    |    return 0;
    |}
    |int parse_wide(struct seq *seq, AVIOContext *pb)
    |{
    |    unsigned int buffer_num[4];
    |    int i;
    |    for (i = 0; i < 4; i++)
    |        buffer_num[i] = avio_rb32(pb);
    |    return fill_wide(seq, buffer_num[1]);
    |}
    |
    |/* a counter no comparison bounds: constant-origin, and unbounded */
    |int more(void);
    |static void pick_counted(struct nut *nut, int idx)
    |{
    |    use_ptr(nut->st[idx]);
    |}
    |void count_up(struct nut *nut)
    |{
    |    int i = 0;
    |    while (more()) {
    |        pick_counted(nut, i);
    |        i++;
    |    }
    |}
    |/* literal arguments */
    |static void pick_fixed(struct nut *nut, int idx)
    |{
    |    use_ptr(nut->st[idx]);
    |}
    |void fixed_callers(struct nut *nut)
    |{
    |    pick_fixed(nut, 0);
    |    pick_fixed(nut, 3);
    |}
    |
    |/* a caller that passes a 32-bit read unbounded: still the attacker's index */
    |static void pick_stream(struct nut *nut, int idx)
    |{
    |    use_ptr(nut->st[idx]);
    |}
    |void parse_header(struct nut *nut, AVIOContext *pb)
    |{
    |    pick_stream(nut, avio_rb32(pb));
    |}
    |
    |/* the same expression without the bound */
    |int no_pid_filter(struct nut *nut, unsigned int pid)
    |{
    |    if (pid == 0 || nut->pids[pid])
    |        return -1;
    |    return 0;
    |}
    |
    |/* mxfdec.c: an enum-typed index into an array sized by the enum's own count */
    |enum SetType { SetA = 0, SetB, SetC, SetTypeNB };
    |struct groups { int g[SetTypeNB]; int small[2]; };
    |int *get_group(struct groups *m, enum SetType type)
    |{
    |    return &m->g[type];
    |}
    |/* ... but not into an array smaller than the enum */
    |int *get_small(struct groups *m, enum SetType type)
    |{
    |    return &m->small[type];
    |}
    |
    |/* an entry point: no caller bounds it */
    |void *api_get(struct nut *nut, int idx)
    |{
    |    return nut->st[idx];
    |}
    |
    |/* a function whose every return is a constant, or an enumerator: the closed range of its
    |   own body bounds what a caller passes its result on */
    |static int pick_slot(unsigned int x)
    |{
    |    if (x)
    |        return 1;
    |    return 0;
    |}
    |static void take_slot(struct nut *nut, int slot)
    |{
    |    use_ptr(nut->st[slot]);
    |}
    |void route_narrow(struct nut *nut, unsigned int x)
    |{
    |    take_slot(nut, pick_slot(x));
    |}
    |enum pns { PNS_INITIAL, PNS_HANDSHAKE, PNS_APP, PNS_NUM };
    |static enum pns enc_to_pns(unsigned int enc_level)
    |{
    |    switch (enc_level) {
    |    case 0: return PNS_INITIAL;
    |    case 1: return PNS_HANDSHAKE;
    |    default: return PNS_APP;
    |    }
    |}
    |static void take_pns(struct nut *nut, int pn_space)
    |{
    |    use_ptr(nut->st[pn_space]);
    |}
    |void route_pns(struct nut *nut, unsigned int enc_level)
    |{
    |    take_pns(nut, enc_to_pns(enc_level));
    |}
    |/* the positive twin: a function that returns what it is handed bounds nothing */
    |static int pick_wide(unsigned int x)
    |{
    |    return x;
    |}
    |static void take_unbounded(struct nut *nut, int slot)
    |{
    |    use_ptr(nut->st[slot]);
    |}
    |void route_wide(struct nut *nut, unsigned int x)
    |{
    |    take_unbounded(nut, pick_wide(x));
    |}
    |
    |/* a counter the loop initialises with an enumerator and bounds with the enum's count */
    |static void take_enum_counter(struct nut *nut, int pn_space)
    |{
    |    use_ptr(nut->st[pn_space]);
    |}
    |void discard_all(struct nut *nut)
    |{
    |    int pn_space;
    |    for (pn_space = PNS_INITIAL; pn_space < PNS_NUM; ++pn_space)
    |        take_enum_counter(nut, pn_space);
    |}
    |""".stripMargin,
    "range.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg, Some(ReaderConfig)).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def boundFindingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet
          .filter(r => r == "MS-BOUND-003" || r == "MS-BOUND-004")

  "an index bounded by construction" should:
    "not report a byte read into a 256-entry table, through the caller" in {
        boundFindingsIn("decode_frame_header") shouldBe empty
    }
    "not report a byte into the 256-wide inner dimension" in {
        boundFindingsIn("pick_channel") shouldBe empty
    }
    "not report a value masked below the capacity" in {
        boundFindingsIn("set_es_id") shouldBe empty
    }
    "report a byte read into a four-entry table (flvdec's multitrack bug)" in {
        boundFindingsIn("set_extradata") should not be empty
    }
    "report it when the byte reaches the caller through a struct field and a conditional" in {
        boundFindingsIn("queue_extradata") should not be empty
    }

  "an enum-typed index" should:
    "not report an array sized by the enum's own count sentinel" in {
        boundFindingsIn("get_group") shouldBe empty
    }
    "report an array smaller than the enum" in {
        boundFindingsIn("get_small") should not be empty
    }

  "a short-circuit guard in the access's own expression" should:
    "bound the index on the right of `||`" in {
        boundFindingsIn("add_pid_filter") shouldBe empty
    }
    "not bound it when the left operand says nothing about its size" in {
        boundFindingsIn("no_pid_filter") should not be empty
    }

  "an index its callers bound" should:
    "not report a loop counter passed directly or two frames up" in {
        boundFindingsIn("deinterleave") shouldBe empty
    }
    "not report a counter declared in its for init and bounded by the loop condition" in {
        boundFindingsIn("add_nal") shouldBe empty
    }
    "not report a signed parameter checked above whose callers pass a byte element" in {
        boundFindingsIn("fill_buffer") shouldBe empty
    }
    "report it when the element is an unsigned int, which converts to a negative int" in {
        boundFindingsIn("fill_wide") should not be empty
    }
    "not report literal arguments" in {
        boundFindingsIn("pick_fixed") shouldBe empty
    }
    "report a counter no comparison bounds" in {
        boundFindingsIn("pick_counted") should not be empty
    }
    "report when a caller passes an unbounded 32-bit read" in {
        boundFindingsIn("pick_stream") should not be empty
    }
    "report at an entry point no caller bounds" in {
        boundFindingsIn("api_get") should not be empty
    }

  "a call of a function whose every return is a constant" should:
    "bound what its caller passes on" in {
        boundFindingsIn("take_slot") shouldBe empty
        boundFindingsIn("take_pns") shouldBe empty
    }
    "not bound anything when the callee returns what it is handed" in {
        boundFindingsIn("take_unbounded") should not be empty
    }

  "a loop counter the caller's loop condition bounds" should:
    "bound what it passes on with enumerator init and bound" in {
        boundFindingsIn("take_enum_counter") shouldBe empty
    }

  "a guard on an access path its caller copies" should:
    "bound the copy the call receives" in {
        boundFindingsIn("take_guarded_copy") shouldBe empty
    }
    "not bound it when the copy has no guard" in {
        boundFindingsIn("take_unguarded_copy") should not be empty
    }
    "not bound it when the path's base is re-stored between the guard and the call" in {
        boundFindingsIn("take_copy_base_written") should not be empty
    }
    "not bound it when the path can be written through another pointer, a call or an increment" in {
        boundFindingsIn("take_copy_alias_written") should not be empty
        boundFindingsIn("take_copy_address_passed") should not be empty
        boundFindingsIn("take_copy_after_call") should not be empty
        boundFindingsIn("take_copy_incremented") should not be empty
    }
end IndexRangeTests

object IndexRangeTests:

  /** The reader widths a project-specific memory-apis config (here, one for FFmpeg) declares: the
    * value ranges come from the vocabulary, never from names built into chen.
    */
  val ReaderConfig: String =
      """{"apis": [
        |  {"name": "avio_r8", "returnRange": [0, 255]},
        |  {"name": "avio_rb16", "returnRange": [0, 65535]},
        |  {"name": "get_bits", "returnBits": 2}
        |]}""".stripMargin
