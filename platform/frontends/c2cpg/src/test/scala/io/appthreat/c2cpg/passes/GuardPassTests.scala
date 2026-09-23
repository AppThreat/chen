package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.{DataFlowCodeToCpgSuite, DataFlowTestCpg}
import io.appthreat.x2cpg.passes.taggers.{ExtentPass, GuardPass, MemoryApiPass}
import io.shiftleft.semanticcpg.language.*

/** GuardPass: `len > cap`, `cap < len`, `len >= cap`, `!(len <= cap)` and an FFMIN clamp are the
  * same fact. The four spellings below must all leave the memcpy's length argument carrying
  * `bounded-above` valued with the capacity - and a guard in the OTHER direction must not.
  */
class GuardPassTests extends DataFlowCodeToCpgSuite:

  private val cpg: DataFlowTestCpg = new DataFlowTestCpg()
      .moreCode(
        """
        |#define FFMIN(a, b) ((a) > (b) ? (b) : (a))
        |#define FFMAX(a, b) ((a) > (b) ? (a) : (b))
        |""".stripMargin,
        "clamps.h"
      )
      .moreCode(
        """
        |#include <string.h>
        |#include "clamps.h"
        |
        |int gt(unsigned char *d, const unsigned char *s, int len, int cap) {
        |    if (len > cap) return -1;
        |    memcpy(d, s, len);
        |    return 0;
        |}
        |
        |int reversed_lt(unsigned char *d, const unsigned char *s, int len, int cap) {
        |    if (cap < len) return -1;
        |    memcpy(d, s, len);
        |    return 0;
        |}
        |
        |int gte(unsigned char *d, const unsigned char *s, int len, int cap) {
        |    if (len >= cap) return -1;
        |    memcpy(d, s, len);
        |    return 0;
        |}
        |
        |int not_lte(unsigned char *d, const unsigned char *s, int len, int cap) {
        |    if (!(len <= cap)) return -1;
        |    memcpy(d, s, len);
        |    return 0;
        |}
        |
        |int or_guard(unsigned char *d, const unsigned char *s, int len, int cap) {
        |    if (len < 0 || len > cap) return -1;
        |    memcpy(d, s, len);
        |    return 0;
        |}
        |
        |int below_only(unsigned char *d, const unsigned char *s, int len) {
        |    if (len < 0) return -1;
        |    memcpy(d, s, len);
        |    return 0;
        |}
        |
        |int then_lt(unsigned char *d, const unsigned char *s, int len, int cap) {
        |    if (len < cap)
        |        memcpy(d, s, len);
        |    return 0;
        |}
        |
        |int then_gt(unsigned char *d, const unsigned char *s, int len, int cap) {
        |    if (len > cap)
        |        memcpy(d, s, len);
        |    return 0;
        |}
        |
        |int clamp_cond(unsigned char *d, const unsigned char *s, int a, int b) {
        |    int n = a < b ? a : b;
        |    memcpy(d, s, n);
        |    return n;
        |}
        |
        |int clamp_macro(unsigned char *buf, int payload_len, int size) {
        |    size = FFMIN(payload_len, size);
        |    memcpy(buf, buf, size);
        |    return size;
        |}
        |
        |int by_extent(unsigned char *s, int n) {
        |    char buf[64];
        |    if (n > sizeof(buf)) return -1;
        |    memcpy(buf, s, n);
        |    return 0;
        |}
        |
        |int unguarded(unsigned char *d, const unsigned char *s, int len) {
        |    memcpy(d, s, len);
        |    return 0;
        |}
        |""".stripMargin,
        "guards.c"
      )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()

  // the mem-len argument of the method's memcpy, with its tags
  private def lenTags(method: String): Set[String] =
      cpg.method
          .name(method)
          .call
          .name("memcpy")
          .l
          .flatMap(_.argument.l.filter(a => a.tag.name("mem-len").l.nonEmpty))
          .flatMap(_.tag.name.l)
          .toSet

  private def lenTagValues(method: String, tag: String): List[String] =
      cpg.method
          .name(method)
          .call
          .name("memcpy")
          .l
          .flatMap(_.argument.l.filter(a => a.tag.name("mem-len").l.nonEmpty))
          .flatMap(_.tag.name(tag).value.l)

  "GuardPass" should {

      "normalise len > cap (early exit) into bounded-above" in {
          val tags = lenTags("gt")
          tags should contain("bounded-above")
          lenTagValues("gt", "bounded-above").exists(_.matches(".*:cap$")) shouldBe true
      }

      "normalise cap < len into the same fact" in {
          lenTags("reversed_lt") should contain("bounded-above")
          // cap < len, negated at the copy: len is bounded above BY cap
          lenTagValues("reversed_lt", "bounded-above").exists(_.matches(".*:cap$")) shouldBe true
      }

      "normalise len >= cap into the same fact" in {
          lenTags("gte") should contain("bounded-above")
      }

      "normalise !(len <= cap) into the same fact" in {
          lenTags("not_lte") should contain("bounded-above")
      }

      "split an || early-exit into both conjuncts" in {
          val tags = lenTags("or_guard")
          tags should contain("bounded-above")
          tags should contain("bounded-below")
      }

      "record a lower-bound-only guard as bounded-below, not bounded-above" in {
          val tags = lenTags("below_only")
          tags should contain("bounded-below")
          tags should not contain "bounded-above"
          lenTagValues("below_only", "bounded-below").exists(_.matches(".*:0$")) shouldBe true
      }

      "bound a copy inside the guarded branch" in {
          lenTags("then_lt") should contain("bounded-above")
      }

      "NOT bound a copy guarded in the wrong direction - the polarity trap" in {
          // if (len > cap) memcpy(...): the condition HOLDS at the copy, so len is not bounded above
          val tags = lenTags("then_gt")
          tags should not contain "bounded-above"
          tags should contain("bounded-below")
      }

      "recognise a hand-written conditional clamp" in {
          lenTags("clamp_cond") should contain("bounded-above")
          lenTagValues("clamp_cond", "bounded-above").head should include("<")
      }

      "recognise an unexpanded FFMIN clamp and value the tag with it" in {
          lenTags("clamp_macro") should contain("bounded-above")
          lenTagValues("clamp_macro", "bounded-above").head should include("FFMIN")
      }

      "emit bounded-by-extent when the bound is the buffer's capacity" in {
          val tags = lenTags("by_extent")
          tags should contain("bounded-above")
          tags should contain("bounded-by-extent")
          lenTagValues("by_extent", "bounded-by-extent") shouldBe List("sizeof:buf")
      }

      "tag nothing on an unguarded copy" in {
          val tags = lenTags("unguarded")
          tags should not contain ("bounded-above")
          tags should not contain ("bounded-below")
          tags should not contain ("bounded-by-extent")
      }

      "emit the memory-safety umbrella alongside every bound tag" in {
          val boundedNodes = cpg.tag
              .name("bounded-above|bounded-below|bounded-by-extent")
              .l
              .flatMap(_._taggedByIn.l)
              .distinct
          boundedNodes should not be empty
          boundedNodes.foreach { n =>
              n.tag.name.l should contain("memory-safety")
          }
      }
  }
end GuardPassTests
