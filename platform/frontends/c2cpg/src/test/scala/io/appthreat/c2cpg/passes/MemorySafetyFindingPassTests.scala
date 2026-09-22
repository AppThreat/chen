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

      "not fire when a guard bounds the length from above" in {
          lenFinding("good_guarded") shouldBe empty
      }

      "not fire when an FFMIN clamp bounds the length" in {
          lenFinding("good_clamped_macro") shouldBe empty
      }

      "not fire on a constant length" in {
          lenFinding("good_constant") shouldBe empty
      }
  }

  "findings" should {

      "carry the memory-safety umbrella, so reachables sees them" in {
          val findingNodes = cpg.tag.name("ms-finding")._taggedByIn.l
          findingNodes should not be empty
          findingNodes.foreach { n =>
              n match
                case s: io.shiftleft.codepropertygraph.generated.nodes.StoredNode =>
                    s.tag.name.l should contain("memory-safety")
                case _ => fail("findings only land on stored nodes")
          }
      }

      "expose rule metadata for the renderer" in {
          MemorySafetyFindingPass.rules("MS-BOUND-001").cwe shouldBe "CWE-787"
          MemorySafetyFindingPass.rules("MS-BOUND-002").kind shouldBe "unbounded-copy"
          MemorySafetyFindingPass.rules("MS-BOUND-002").confidence shouldBe "medium"
      }
  }
end MemorySafetyFindingPassTests
