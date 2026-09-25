package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** The adversarial review of the MS-BOUND-003/004 precision change (NOTES-bound003-review.md in the
  * corpus): every method below indexes out of bounds for some input, and the first cut of the
  * change silenced each of them. Every test expects a finding, except the informational ones: R3b
  * (a loop counter is constant-origin, never an attacker index) and R4/R4b/R4c/R13, whose
  * arithmetic index ValueOriginPass calls `mixed` - a gap older than this change.
  */
class IndexRangeSoundnessTests extends DataFlowCodeToCpgSuite:

  private def runPasses(c: Cpg): Unit =
    new MemorySemanticsPass(c).createAndApply()
    new MemoryApiPass(c, Some(IndexRangeTests.ReaderConfig)).createAndApply()
    new ExtentPass(c).createAndApply()
    new GuardPass(c).createAndApply()
    new ValueOriginPass(c).createAndApply()
    new IntegerWidthPass(c).createAndApply()
    new AllocationStatePass(c).createAndApply()
    new MemorySafetyFindingPass(c).createAndApply()

  private val cpg = code(
    """
    |typedef struct AVIOContext AVIOContext;
    |int avio_r8(AVIOContext *pb);
    |unsigned int avio_rb32(AVIOContext *pb);
    |void use_ptr(void *p);
    |
    |struct nut { void *st[4]; void *ch[4][256]; };
    |
    |/* R1: a literal past the end - isLiteralOnly never compares it to the capacity */
    |static void pick_lit(struct nut *nut, int idx) { use_ptr(nut->st[idx]); }
    |void lit_caller(struct nut *nut) { pick_lit(nut, 7); }
    |
    |/* R2: a negative literal */
    |static void pick_neg(struct nut *nut, int idx) { use_ptr(nut->st[idx]); }
    |void neg_caller(struct nut *nut) { pick_neg(nut, -1); }
    |
    |/* R3: a loop counter whose bound (8) exceeds the capacity (4) */
    |static void pick_loop(struct nut *nut, int idx) { use_ptr(nut->st[idx]); }
    |void loop_caller(struct nut *nut)
    |{
    |    int i;
    |    for (i = 0; i < 8; i++)
    |        pick_loop(nut, i);
    |}
    |
    |/* R4: the callee offsets a byte: idx + 1 reaches 256 */
    |static void pick_off(struct nut *nut, int idx) { use_ptr(nut->ch[0][idx + 1]); }
    |void off_caller(struct nut *nut, AVIOContext *pb) { pick_off(nut, avio_r8(pb)); }
    |
    |/* R4b: the callee offsets a literal: 3 + 2 reaches 5 */
    |static void pick_off_lit(struct nut *nut, int idx) { use_ptr(nut->st[idx + 2]); }
    |void off_lit_caller(struct nut *nut) { pick_off_lit(nut, 3); }
    |
    |/* R5: a byte stored in a signed char is -128..127, not 0..255 */
    |void trunc_local(struct nut *nut, AVIOContext *pb)
    |{
    |    signed char c = avio_r8(pb);
    |    use_ptr(nut->ch[0][c]);
    |}
    |
    |/* R6: the same truncation at parameter binding */
    |static void pick_s8(struct nut *nut, signed char idx) { use_ptr(nut->ch[0][idx]); }
    |void s8_caller(struct nut *nut, AVIOContext *pb) { pick_s8(nut, avio_r8(pb)); }
    |
    |/* R7: an unsigned 32-bit read bound to a signed int, checked above only (the one-sided
    |   CVE-2026-75146 shape): 0xffffffff arrives as -1 */
    |static void *pick_signed(struct nut *nut, int idx, int n)
    |{
    |    if (idx >= n)
    |        return 0;
    |    return nut->st[idx];
    |}
    |void *signed_caller(struct nut *nut, AVIOContext *pb) { return pick_signed(nut, avio_rb32(pb), 4); }
    |
    |/* R7b: the same through an explicit (int) cast */
    |static void *pick_cast(struct nut *nut, int idx, int n)
    |{
    |    if (idx >= n)
    |        return 0;
    |    return nut->st[idx];
    |}
    |void *cast_caller(struct nut *nut, AVIOContext *pb) { return pick_cast(nut, (int)avio_rb32(pb), 4); }
    |
    |/* R8: one direct caller passes 0, a function-pointer caller passes a 32-bit read */
    |static void *pick_fp(struct nut *nut, int idx) { return nut->st[idx]; }
    |void *fp_direct(struct nut *nut) { return pick_fp(nut, 0); }
    |void *fp_indirect(struct nut *nut, AVIOContext *pb)
    |{
    |    void *(*h)(struct nut *, int) = pick_fp;
    |    return h(nut, avio_rb32(pb));
    |}
    |
    |/* R10: an enum with no count sentinel into an array one short of it (BLUE -> v[2]) */
    |enum Color { RED, GREEN, BLUE };
    |struct pal { int v[2]; };
    |int get_color(struct pal *p, enum Color c) { return p->v[c]; }
    |
    |/* R11: an enum variable assigned straight from a byte read (C converts implicitly) */
    |enum SetType { SetA = 0, SetB, SetC, SetTypeNB };
    |struct groups { int g[SetTypeNB]; };
    |int *group_from_read(struct groups *m, AVIOContext *pb)
    |{
    |    enum SetType t = avio_r8(pb);
    |    return &m->g[t];
    |}
    |
    |/* R12: the loop condition held before the argument was redefined */
    |static void pick_redef(struct nut *nut, int idx) { use_ptr(nut->st[idx]); }
    |void redef_caller(struct nut *nut, AVIOContext *pb)
    |{
    |    unsigned int n = 0;
    |    while (n < 4) {
    |        n = avio_rb32(pb);
    |        pick_redef(nut, n);
    |    }
    |}
    |
    |/* R13: 010 is octal 8, not 10: x >> 8 of a 16-bit value reaches 255 */
    |struct oct { int t[64]; };
    |int oct_idx(struct oct *o, unsigned short x) { return o->t[x >> 010]; }
    |
    |/* R13c: 010 is octal 8, inside st9[9]; read as decimal 10 it would not be */
    |struct nine { void *st9[9]; };
    |static void pick_oct(struct nine *n, int idx) { use_ptr(n->st9[idx]); }
    |void oct_caller(struct nine *n) { pick_oct(n, 010); }
    |
    |/* R14: a global the callee overwrites between the constant store and the call */
    |static int g_idx;
    |static void set_g(AVIOContext *pb) { g_idx = avio_rb32(pb); }
    |static void pick_g(struct nut *nut, int idx) { use_ptr(nut->st[idx]); }
    |void global_caller(struct nut *nut, AVIOContext *pb)
    |{
    |    g_idx = 0;
    |    set_g(pb);
    |    pick_g(nut, g_idx);
    |}
    |
    |/* R4c: the callee derives the index from the parameter: j = idx + 1 reaches 256 */
    |static void pick_derived(struct nut *nut, int idx)
    |{
    |    int j = idx + 1;
    |    use_ptr(nut->ch[0][j]);
    |}
    |void derived_caller(struct nut *nut, AVIOContext *pb) { pick_derived(nut, avio_r8(pb)); }
    |
    |/* R4d: the callee increments the parameter first */
    |static void pick_inc(struct nut *nut, int idx)
    |{
    |    idx++;
    |    use_ptr(nut->ch[0][idx]);
    |}
    |void inc_caller(struct nut *nut, AVIOContext *pb) { pick_inc(nut, avio_r8(pb)); }
    |
    |/* R15: two frames up the parameter is matched by NAME - mid overwrote ch before passing it */
    |static void pick_mid(struct nut *nut, int idx) { use_ptr(nut->st[idx]); }
    |static void mid(struct nut *nut, int ch, AVIOContext *pb)
    |{
    |    ch = avio_rb32(pb);
    |    pick_mid(nut, ch);
    |}
    |void top_caller(struct nut *nut, AVIOContext *pb) { mid(nut, 0, pb); }
    |
    |/* R3b / R12b: the in-method twins of R3 and R12, for comparison */
    |void loop_inline(struct nut *nut, int unused)
    |{
    |    int i;
    |    for (i = 0; i < 8; i++)
    |        use_ptr(nut->st[i]);
    |}
    |/* R16: avidec.c's shape - a sibling case's early exit on an EARLIER iteration's value is read
    |   as a bound at this call (controlledBy through the loop back edge, holdsAt = false) */
    |static void pick_sib(struct nut *nut, unsigned int idx) { use_ptr(nut->st[idx]); }
    |void sib_caller(struct nut *nut, AVIOContext *pb)
    |{
    |    for (;;) {
    |        int tag = avio_r8(pb);
    |        unsigned int n = avio_rb32(pb);
    |        switch (tag) {
    |        case 1:
    |            if (n > 3)
    |                return;
    |            break;
    |        case 2:
    |            pick_sib(nut, n);
    |            break;
    |        }
    |    }
    |}
    |void sib_inline(struct nut *nut, AVIOContext *pb, unsigned int m)
    |{
    |    for (;;) {
    |        int tag = avio_r8(pb);
    |        m = avio_rb32(pb);
    |        switch (tag) {
    |        case 1:
    |            if (m > 3)
    |                return;
    |            break;
    |        case 2:
    |            use_ptr(nut->st[m]);
    |            break;
    |        }
    |    }
    |}
    |void redef_inline(struct nut *nut, AVIOContext *pb, int k)
    |{
    |    while (k < 4) {
    |        k = avio_rb32(pb);
    |        use_ptr(nut->st[k]);
    |    }
    |}
    |""".stripMargin,
    "review.c"
  )
  runPasses(cpg)

  /* R9: two translation units each define a static pick_dup; only b.c calls its own with 0 */
  private val cpg2 = code(
    """
    |void use_ptr(void *p);
    |struct nut { void *st[4]; };
    |static void pick_dup(struct nut *nut, int idx) { use_ptr(nut->st[idx]); }
    |void (*const table[])(struct nut *, int) = { pick_dup };
    |""".stripMargin,
    "a.c"
  ).moreCode(
    """
    |struct nut { void *st[4]; };
    |static void pick_dup(struct nut *nut, int idx) { (void)nut; (void)idx; }
    |void b_caller(struct nut *nut) { pick_dup(nut, 0); }
    |""".stripMargin,
    "b.c"
  )
  runPasses(cpg2)

  private def boundFindingsIn(c: Cpg, method: String, file: Option[String] = None): Set[String] =
      c.method.nameExact(method)
          .filter(m => file.forall(f => m.filename.endsWith(f)))
          .ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet
          .filter(r => r == "MS-BOUND-003" || r == "MS-BOUND-004" || r == "MS-BOUND-005")

  private def allFindingsIn(c: Cpg, method: String): Set[String] =
      c.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  private def report(c: Cpg, method: String, file: Option[String] = None): Set[String] =
    val f = boundFindingsIn(c, method, file)
    info(s"$method: ${if f.isEmpty then "silent" else f.mkString(",")}")
    f

  "235cbf60's caller evidence" should:
    "R1 report a literal argument past the capacity" in {
        report(cpg, "pick_lit") should not be empty
    }
    "R2 report a negative literal argument" in {
        report(cpg, "pick_neg") should not be empty
    }
    "R3 report a loop counter whose bound exceeds the capacity" in {
        report(cpg, "pick_loop") should not be empty
    }
    "R4 (informational: the index is `mixed` caller-param+constant, which the rule has never read as attacker-controlled)" in {
        report(cpg, "pick_off")
    }
    "R4b (informational: the index is `mixed` caller-param+constant, which the rule has never read as attacker-controlled)" in {
        report(cpg, "pick_off_lit")
    }
    "R8 report a method a function pointer also reaches" in {
        report(cpg, "pick_fp") should not be empty
    }
    "R9 report a static method whose only direct call is to a same-named static elsewhere" in {
        info(s"a.c pick_dup callIn: ${cpg2.method.nameExact("pick_dup").l.map(m =>
                m.filename + " <- " + m._callIn.collectAll[io.shiftleft.codepropertygraph.generated
                    .nodes.Call].method.name.l.mkString(",")
            ).mkString("; ")}")
        report(cpg2, "pick_dup", Some("a.c")) should not be empty
    }
    "R12 report an argument redefined after the loop condition that bounded it" in {
        report(cpg, "pick_redef") should not be empty
    }
    "R14 report a global argument a callee overwrote" in {
        report(cpg, "pick_g") should not be empty
    }
    "R4c (informational: the index is `mixed` caller-param+constant, which the rule has never read as attacker-controlled)" in {
        report(cpg, "pick_derived")
    }
    "R4d report a bounded argument the callee increments" in {
        report(cpg, "pick_inc") should not be empty
    }
    "R15 report when the frame-2 parameter was overwritten before the call" in {
        report(cpg, "pick_mid") should not be empty
    }
    "R16 report when the only 'bound' is a sibling case's exit on an earlier iteration" in {
        report(cpg, "pick_sib") should not be empty
    }
    "R16b report the in-method twin: GuardPass reads only dominating guards" in {
        report(cpg, "sib_inline") should not be empty
    }
    "R3b (in-method twin of R3, informational)" in {
        info(s"all findings: ${allFindingsIn(cpg, "loop_inline")}")
        report(cpg, "loop_inline")
    }
    "R12b report the in-method twin: the guard tested an older value" in {
        report(cpg, "redef_inline") should not be empty
    }

  "235cbf60's value ranges" should:
    "R5 report a byte stored in a signed char (negative index)" in {
        report(cpg, "trunc_local") should not be empty
    }
    "R6 report a byte bound to a signed char parameter" in {
        report(cpg, "pick_s8") should not be empty
    }
    "R7 report an unsigned read bound to a signed int checked above only" in {
        report(cpg, "pick_signed") should not be empty
    }
    "R7b report the same through an (int) cast" in {
        report(cpg, "pick_cast") should not be empty
    }
    "R13 (informational: the index is `mixed` caller-param+constant, which the rule has never read as attacker-controlled)" in {
        report(cpg, "oct_idx")
    }

  "an octal literal argument" should:
    "R13c be read as octal, 010 = 8, inside a nine-entry array" in {
        report(cpg, "pick_oct") shouldBe empty
    }

  "235cbf60's enum arm" should:
    "R10 report an enum with no sentinel into an array one short" in {
        report(cpg, "get_color") should not be empty
    }
    "R11 report an enum variable assigned from a byte read" in {
        report(cpg, "group_from_read") should not be empty
    }
end IndexRangeSoundnessTests
