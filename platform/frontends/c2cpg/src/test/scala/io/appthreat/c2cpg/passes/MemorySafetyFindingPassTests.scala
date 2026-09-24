package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.{DataFlowCodeToCpgSuite, DataFlowTestCpg}
import io.appthreat.x2cpg.passes.taggers.{
    ExtentPass,
    GuardPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    ValueOriginPass
}
import io.shiftleft.semanticcpg.language.*

/** MemorySafetyFindingPass: each rule fires on its corpus fixture shape and does NOT fire on the
  * paired correctly-written variant. The fixtures mirror `c/ffmpeg-shapes/size_param_contract.c`
  * (CVE-2026-75143) and the unbounded-copy shape behind CVE-2026-75144.
  */
class MemorySafetyFindingPassTests extends DataFlowCodeToCpgSuite:

  private val cpg: DataFlowTestCpg = new DataFlowTestCpg()
      .moreCode(
        """
        |#define FFMIN(a, b) ((a) > (b) ? (b) : (a))
        |""".stripMargin,
        "clamps.h"
      )
      .moreCode(
        """
        |#include <string.h>
        |#include <stdlib.h>
        |#include <unistd.h>
        |#include "clamps.h"
        |
        |struct data_block { unsigned char *payload; int payload_len; };
        |
        |/* ---- MS-BOUND-001: the size_param_contract.c shapes ---- */
        |
        |int bad_overwrites_size_param(unsigned char *buf, int size, struct data_block *db)
        |{
        |    size = db->payload_len;
        |    memcpy(buf, db->payload, size);
        |    return size;
        |}
        |
        |int bad_ignores_size_param(unsigned char *buf, int size, struct data_block *db)
        |{
        |    (void)size;
        |    memcpy(buf, db->payload, db->payload_len);
        |    return db->payload_len;
        |}
        |
        |int good_clamped(unsigned char *buf, int size, struct data_block *db)
        |{
        |    int n = db->payload_len < size ? db->payload_len : size;
        |    memcpy(buf, db->payload, n);
        |    return n;
        |}
        |
        |int good_rejects(unsigned char *buf, int size, struct data_block *db)
        |{
        |    if (db->payload_len > size) return -1;
        |    memcpy(buf, db->payload, db->payload_len);
        |    return db->payload_len;
        |}
        |
        |int good_uses_cap(unsigned char *buf, int size, struct data_block *db)
        |{
        |    memcpy(buf, db->payload, size);
        |    return size;
        |}
        |
        |/* ---- MS-BOUND-002: the unbounded-copy shapes ---- */
        |
        |int bad_unbounded(unsigned char *d, const unsigned char *s, int size)
        |{
        |    memcpy(d, s, size);
        |    return 0;
        |}
        |
        |int bad_tainted(int fd, unsigned char *tmp, unsigned char *d, const unsigned char *s)
        |{
        |    int n = read(fd, tmp, 256);
        |    memcpy(d, s, n);
        |    return n;
        |}
        |
        |int good_guarded(unsigned char *d, const unsigned char *s, int size, int cap)
        |{
        |    if (size > cap) return -1;
        |    memcpy(d, s, size);
        |    return 0;
        |}
        |
        |int good_clamped_macro(unsigned char *d, const unsigned char *s, int size, int cap)
        |{
        |    size = FFMIN(size, cap);
        |    memcpy(d, s, size);
        |    return 0;
        |}
        |
    |int good_constant(unsigned char *d, const unsigned char *s)
    |{
    |    memcpy(d, s, 64);
    |    return 0;
    |}
    |
    |/* ---- part 9: the self-sized destination (FFmpeg's dominant correct shape) ---- */
    |
    |/* dashdec.c: the buffer was allocated with this very length */
    |char *good_self_sized_alloc(const char *url, int max_url_size)
    |{
    |    char *tmp = (char *)malloc(max_url_size);
    |    if (!tmp) return NULL;
    |    memcpy(tmp, url, max_url_size);
    |    return tmp;
    |}
    |
    |/* matroskadec.c: the allocation is a SUM the copy length is a term of, one definition
    |   level away (`pkt_size = isize + header_size`) */
    |int good_self_sized_sum(const unsigned char *data, int isize, int header_size)
    |{
    |    int pkt_size = isize + header_size;
    |    unsigned char *pkt_data = (unsigned char *)malloc(pkt_size + 64);
    |    if (!pkt_data) return -1;
    |    memcpy(pkt_data + header_size, data, isize);
    |    return 0;
    |}
    |
    |/* mpegtsenc.c: one multi-term sum names every copied fragment */
    |int good_self_sized_terms(const unsigned char *aud, int aud_size, const unsigned char *extra, int extra_size)
    |{
    |    unsigned char *data = (unsigned char *)malloc(4 + aud_size + extra_size);
    |    if (!data) return -1;
    |    memcpy(data + 4, aud, aud_size);
    |    memcpy(data + 4 + aud_size, extra, extra_size);
    |    return 0;
    |}
    |
    |/* hls.c: an in-place compaction - the destination and the source share a root */
    |void good_in_place_strip(unsigned char *buf, int buf_size, int strip, int len)
    |{
    |    memmove(buf, buf + strip, len);
    |}
    |
    |/* the hls shape exactly: the length is a dereference, not a local */
    |void good_in_place_deref_len(unsigned char *buf, int buf_size, int tag_got_bytes, int *lenp)
    |{
    |    *lenp -= tag_got_bytes;
    |    memmove(buf, buf + tag_got_bytes, *lenp);
    |}
    |
    |/* the loop-carried hls shape: the compaction runs inside the read loop */
    |void good_in_place_loop(unsigned char *buf, int tag_got_bytes, int *lenp)
    |{
    |    int pos = 0;
    |    for (;;)
    |    {
    |        if (*lenp < 10)
    |            break;
    |        *lenp -= tag_got_bytes;
    |        memmove(buf, buf + tag_got_bytes, *lenp);
    |        pos += tag_got_bytes;
    |    }
    |}
    |
    |/* dashdec.c: the length is derived from the destination itself - clearing strlen(dst)
    |   bytes of dst cannot cross dst */
    |void good_strlen_of_dst(char *tmp_str, int tmp_max_url_size)
    |{
    |    memset(tmp_str, 0, strlen(tmp_str));
    |    memset(tmp_str + 1, 0, strlen(tmp_str));
    |}
    |
    |/* a destination through a struct member resolves no allocation here - the packet library
    |   sized it (av_new_packet), and this rule stays out of that boundary: still a finding */
    |struct p9_pkt { unsigned char *data; };
    |int p9_still_bad_packet_data(struct p9_pkt *p, const unsigned char *s, int len)
    |{
    |    memcpy(p->data, s, len);
    |    return 0;
    |}
    |
    |/* an allocation that does not contain the length is no excuse */
    |int p9_still_bad_other_size(const unsigned char *s, int len)
    |{
    |    unsigned char *d = (unsigned char *)malloc(16);
    |    memcpy(d, s, len);
    |    return 0;
    |}
    |
    |/* ---- F3 (part 6): the guard in the ELSE branch ---- */
        |
        |/* the bounds check's REJECT path is the then-branch and the copy lives in the
        |   else: c2cpg types the else as controlStructureType=ELSE with the block's own
        |   parser type, and GuardPass matched the parser type only - so the condition was
        |   read as HOLDING at the copy, the disjunction could not be split, no bound was
        |   emitted, and this fired (codec2.c:87's shape, one of a third of BOUND-003's
        |   per-tree findings) */
        |int good_else_guarded_copy(unsigned char *d, const unsigned char *s, int size, int cap)
        |{
        |    if (size < 0 || size > cap)
        |        return -1;
        |    else
        |        memcpy(d, s, size);
        |    return 0;
        |}
        |
        |int good_else_guarded_index(int mode)
        |{
        |    int frame_size_table[9];
        |    if (mode < 0 || mode > 8)
        |        return 0;
        |    else
        |        return frame_size_table[mode];
        |}
        |
        |/* ---- C3: the caller-param arm is interprocedural ---- */
        |
        |static int helper_constant(unsigned char *d, const unsigned char *s, int size)
        |{
        |    memcpy(d, s, size);
        |    return size;
        |}
        |
        |static int helper_variable(unsigned char *d, const unsigned char *s, int size)
        |{
        |    memcpy(d, s, size);
        |    return size;
        |}
        |
        |void call_constant(unsigned char *d, const unsigned char *s)
        |{
        |    helper_constant(d, s, 32);
        |}
        |
        |void call_variable(unsigned char *d, const unsigned char *s, int n)
        |{
        |    helper_variable(d, s, n);
        |}
        |
        |void alloc_only(int n)
        |{
        |    unsigned char *p = malloc(n);
        |    free(p);
        |}
        |
        |/* ---- C4: MS-BOUND-003/004, index bounds ---- */
        |
        |struct rep { struct frag **fragments; long long cur_seq_no; int n_fragments; };
        |struct frag { int x; };
        |struct repu { unsigned int pos; };
        |
        |/* the CVE-2026-75146 shape: bounded above only, signed field index */
        |int bad_half_bounded(struct rep *pls)
        |{
        |    struct frag *seg_ptr = NULL;
        |    if (pls->cur_seq_no < pls->n_fragments)
        |        seg_ptr = pls->fragments[pls->cur_seq_no];
        |    return seg_ptr != NULL;
        |}
        |
        |/* the fixed tree: the >= 0 conjunct is the bound the rule reads */
        |int good_both_bounded(struct rep *pls)
        |{
        |    struct frag *seg_ptr = NULL;
        |    if (pls->cur_seq_no >= 0 && pls->cur_seq_no < pls->n_fragments)
        |        seg_ptr = pls->fragments[pls->cur_seq_no];
        |    return seg_ptr != NULL;
        |}
        |
        |/* attacker-controlled index into a known capacity, unbounded: the write arm */
        |int bad_attacker_index(int idx)
        |{
        |    char buf[64];
        |    buf[idx] = 'x';
        |    return idx;
        |}
        |
        |/* the same shape on the read side */
        |int bad_attacker_read(int idx)
        |{
        |    char buf[64];
        |    return buf[idx];
        |}
        |
        |/* a loop index is a constant at heart: neither arm fires */
        |int loop_ok(int n)
        |{
        |    char buf[64];
        |    int i;
        |    int s = 0;
        |    for (i = 0; i < n && i < 64; i++)
        |        s += buf[i];
        |    return s;
        |}
        |
        |/* a struct-field index that cannot go negative is not the negative-index shape */
        |int unsigned_index(struct repu *r)
        |{
        |    char buf[8];
        |    return buf[r->pos];
        |}
        |""".stripMargin,
        "findings.c"
      )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  // (rule ids found on mem-len arguments of the method's memory calls, with lines)
  private def findingsIn(method: String): List[(String, Int)] =
      cpg.method
          .name(method)
          .call
          .name("memcpy|read")
          .l
          .flatMap(_.argument.l)
          .filter(a => a.tag.name("ms-finding").l.nonEmpty)
          .flatMap(a =>
              a.tag.name("ms-finding").value.l.map(v =>
                  (v, a.lineNumber.map(_.toInt).getOrElse(-1))
              )
          )

  private def lenFinding(method: String): Set[String] =
      cpg.method
          .name(method)
          .call
          .name("memcpy")
          .l
          .flatMap(_.argument.l.filter(a => a.tag.name("mem-len").l.nonEmpty))
          .flatMap(_.tag.name("ms-finding").value.l)
          .toSet

  /** Rule ids on the index arguments of the method's array accesses. */
  private def indexFindings(method: String): Set[String] =
      cpg.method
          .name(method)
          .call
          .name("<operator>.indexAccess|<operator>.indirectIndexAccess")
          .l
          .flatMap(_.argumentOption(2))
          .flatMap(_.tag.name("ms-finding").value.l)
          .toSet

  "MS-BOUND-001" should {

      "fire when the capacity parameter is clobbered before the write" in {
          lenFinding("bad_overwrites_size_param") shouldBe Set("MS-BOUND-001")
      }

      "fire when the capacity parameter is simply never used" in {
          lenFinding("bad_ignores_size_param") shouldBe Set("MS-BOUND-001")
      }

      "not fire when the length is clamped to the capacity" in {
          lenFinding("good_clamped") shouldBe empty
      }

      "not fire when the copy is guarded against the capacity" in {
          lenFinding("good_rejects") shouldBe empty
      }

      "not fire when the capacity parameter IS the length" in {
          lenFinding("good_uses_cap") shouldBe empty
      }
  }

  "MS-BOUND-002" should {

      "fire on an unbounded caller-controlled length" in {
          lenFinding("bad_unbounded") shouldBe Set("MS-BOUND-002")
      }

      "fire on an unbounded untrusted-read length" in {
          lenFinding("bad_tainted") shouldBe Set("MS-BOUND-002")
      }

      "stand down when the destination was sized from this copy's length (part 9)" in {
          // FFmpeg's dominant correct shape - 9 of one tree's 38 findings, all false: the
          // allocation's own argument (or a sum containing it, one def level away) IS the
          // length, and an in-place compaction cannot cross the buffer it already holds
          Seq("good_self_sized_alloc", "good_self_sized_sum", "good_self_sized_terms",
            "good_in_place_strip", "good_in_place_deref_len", "good_in_place_loop",
            "good_strlen_of_dst").foreach { m =>
              withClue(m) { lenFinding(m) shouldBe empty }
          }
      }

      "keep firing through a struct-member destination or an unrelated allocation size" in {
          lenFinding("p9_still_bad_packet_data") shouldBe Set("MS-BOUND-002")
          lenFinding("p9_still_bad_other_size") shouldBe Set("MS-BOUND-002")
      }

      "not fire when a guard bounds the length from above" in {
          lenFinding("good_guarded") shouldBe empty
      }

      "not fire when an FFMIN clamp bounds the length" in {
          lenFinding("good_clamped_macro") shouldBe empty
      }

      "not fire on a constant length" in {
          lenFinding("good_constant") shouldBe empty
      }

      "not fire when the guard's in-range path is the ELSE branch (F3)" in {
          lenFinding("good_else_guarded_copy") shouldBe empty
          indexFindings("good_else_guarded_index") shouldBe empty
      }
  }

  "MS-BOUND-002 under C3 (interprocedural caller-param arm)" should {

      "stay silent when every call site passes a provable constant" in {
          lenFinding("helper_constant") shouldBe empty
      }

      "fire when a call site passes a non-constant for the length" in {
          lenFinding("helper_variable") shouldBe Set("MS-BOUND-002")
      }

      "keep firing on an uncalled helper: no intra-tree callers means externally reachable" in {
          lenFinding("bad_unbounded") shouldBe Set("MS-BOUND-002")
      }

      "not report an allocation size: CWE-787 needs a destination buffer" in {
          // MS-BOUND-002's silence only: an uncapped allocation-size site is MS-ALLOC-008's
          // own question and may legitimately carry that finding
          cpg.method.name("alloc_only").call.name("malloc").l.flatMap(_.argument.l)
              .flatMap(_.tag.name("ms-finding").value.l) should not contain "MS-BOUND-002"
      }
  }

  "MS-BOUND-003/004 (C4 index bounds)" should {

      "fire on a signed field index bounded only above - the negative-index shape" in {
          indexFindings("bad_half_bounded") shouldBe Set("MS-BOUND-005")
      }

      "go quiet when the fixed tree adds the >= 0 conjunct" in {
          indexFindings("good_both_bounded") shouldBe empty
      }

      "fire the write arm on an attacker index into a known capacity" in {
          indexFindings("bad_attacker_index") shouldBe Set("MS-BOUND-004")
      }

      "fire the read arm on the read side" in {
          indexFindings("bad_attacker_read") shouldBe Set("MS-BOUND-003")
      }

      "stay silent on a loop index, whose origin is a constant" in {
          indexFindings("loop_ok") shouldBe empty
      }

      "stay silent on an unsigned field index: it cannot go negative" in {
          indexFindings("unsigned_index") shouldBe empty
      }
  }

  "findings" should {

      "carry the memory-safety umbrella, so reachables sees them" in {
          val findingNodes = cpg.tag.name("ms-finding")._taggedByIn.l
          findingNodes should not be empty
          findingNodes.foreach { n =>
              n.tag.name.l should contain("memory-safety")
          }
      }

      "expose rule metadata for the renderer" in {
          MemorySafetyFindingPass.rules("MS-BOUND-001").cwe shouldBe "CWE-787"
          MemorySafetyFindingPass.rules("MS-BOUND-002").kind shouldBe "unbounded-copy"
          MemorySafetyFindingPass.rules("MS-BOUND-002").confidence shouldBe "medium"
      }
  }
end MemorySafetyFindingPassTests
