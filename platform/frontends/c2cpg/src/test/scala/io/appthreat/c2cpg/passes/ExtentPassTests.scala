package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ExtentPass, MemoryApiPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** ExtentPass: one row of the table per fixture, including the negative - a pointer of genuinely
  * unknown provenance tags `unknown`, never a guess.
  */
class ExtentPassTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <string.h>
    |#include <stdlib.h>
    |
    |#define SZ 128
    |
    |struct blk {
    |    unsigned char payload[64];
    |    unsigned char *data;
    |    int data_len;
    |};
    |
    |struct one { unsigned char *buf; };
    |struct two { unsigned char *buf; };
    |struct many { unsigned char *buf; };
    |
    |unsigned char *get_buf(void);
    |
    |void const_local(unsigned char *src, int n) {
    |    char buf[SZ];
    |    memcpy(buf, src, n);
    |}
    |
    |void const_member(struct blk *b, unsigned char *src, int n) {
    |    memcpy(b->payload, src, n);
    |}
    |
    |void sizeof_alloc(unsigned char *src, int n) {
    |    struct blk *p = malloc(sizeof(struct blk));
    |    memcpy(p, src, n);
    |}
    |
    |void sizeof_in_copy(unsigned char *buf, unsigned char *src) {
    |    memcpy(buf, src, sizeof(buf));
    |}
    |
    |void alloc_row(unsigned char *src, int n) {
    |    unsigned char *p = malloc(256);
    |    memcpy(p, src, n);
    |}
    |
    |void param_row(unsigned char *buf, int size, unsigned char *src, int n) {
    |    memcpy(buf, src, n);
    |}
    |
    |void field_row(struct blk *b, unsigned char *src, int n) {
    |    memcpy(b->data, src, n);
    |}
    |
    |void unknown_row(unsigned char *src, int n) {
    |    unsigned char *p = get_buf();
    |    memcpy(p, src, n);
    |}
    |
    |void additive_literal(unsigned char *src, int n) {
    |    char buf[SZ];
    |    memcpy(buf + 4, src, n);
    |}
    |
    |void additive_composed(unsigned char *src, int n) {
    |    char buf[SZ];
    |    memcpy(buf + 2 + 4, src, n);
    |}
    |
    |void additive_variable(unsigned char *src, int off, int n) {
    |    char buf[SZ];
    |    memcpy(buf + off, src, n);
    |}
    |
    |void subtractive_literal(unsigned char *src, int n) {
    |    char buf[SZ];
    |    memcpy(buf - 4, src, n);
    |}
    |
    |void additive_past_end(unsigned char *src, int n) {
    |    char buf[8];
    |    memcpy(buf + 16, src, n);
    |}
    |
    |void additive_unknown_base(unsigned char *src, int n) {
    |    unsigned char *p = get_buf();
    |    memcpy(p + 4, src, n);
    |}
    |
    |void additive_param_base(unsigned char *buf, int size, unsigned char *src, int n) {
    |    memcpy(buf + 4, src, n);
    |}
    |
    |void addressof_scalar_typed_by_copy(unsigned char *src) {
    |    int dst;
    |    memcpy(&dst, src, sizeof(dst));
    |}
    |
    |void addressof_index(unsigned char *src, int i, int n) {
    |    char buf[SZ];
    |    memcpy(&buf[i], src, n);
    |}
    |
    |void member_from_alloc(unsigned char *src, int n) {
    |    struct one *w = malloc(sizeof(struct one));
    |    w->buf = malloc(256);
    |    memcpy(w->buf, src, n);
    |}
    |
    |void member_from_alloc_sizeof(unsigned char *src, int n) {
    |    struct two w;
    |    w.buf = malloc(sizeof(struct two));
    |    memcpy(w.buf, src, n);
    |}
    |
    |void member_from_two_allocs(unsigned char *src, int n) {
    |    struct many w;
    |    if (n > 0)
    |        w.buf = malloc(32);
    |    else
    |        w.buf = malloc(64);
    |    memcpy(w.buf, src, n);
    |}
    |""".stripMargin,
    "extent.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()

  private def dstExtentOf(methodName: String): List[String] =
      cpg.method
          .name(methodName)
          .call
          .name("memcpy|snprintf")
          .l
          .flatMap(_.argument.l)
          .flatMap(_.tag.name("extent").value.l)

  "ExtentPass" should {

      "derive const from a declared local array, through a #define" in {
          dstExtentOf("const_local") shouldBe List("const:128")
      }

      "derive const from a struct member array" in {
          dstExtentOf("const_member") shouldBe List("const:64")
      }

      "derive sizeof from the allocation that produced the pointer" in {
          dstExtentOf("sizeof_alloc") shouldBe List("sizeof:sizeof(struct blk)")
      }

      "derive sizeof from the copy's own length argument against the same buffer" in {
          dstExtentOf("sizeof_in_copy") shouldBe List("sizeof:buf")
      }

      "derive alloc from the size argument of the producing mem-alloc call" in {
          val extent = dstExtentOf("alloc_row").head
          extent.startsWith("alloc:") shouldBe true
          // the value names the size-argument node of the malloc, so the fact is traceable
          val sizeNodeId = extent.stripPrefix("alloc:").toLong
          cpg.literal.code("256").l.map(_.id) should contain(sizeNodeId)
      }

      "derive param from an adjacent capacity parameter, without consulting names" in {
          dstExtentOf("param_row") shouldBe List("param:size")
      }

      "derive field from a struct member holding the length beside the buffer" in {
          dstExtentOf("field_row") shouldBe List("field:data_len")
      }

      "tag unknown on a pointer of genuinely unknown provenance, rather than guessing" in {
          dstExtentOf("unknown_row") shouldBe List("unknown")
      }

      "reduce a const extent by a literal offset" in {
          dstExtentOf("additive_literal") shouldBe List("const:124")
      }

      "reduce a const extent through composed literal offsets" in {
          dstExtentOf("additive_composed") shouldBe List("const:122")
      }

      "say offset:, not a capacity, when the offset is not a literal" in {
          dstExtentOf("additive_variable") shouldBe List("offset:const:128")
      }

      "say offset: for a subtraction, whose start may be before the buffer" in {
          dstExtentOf("subtractive_literal") shouldBe List("offset:const:128")
      }

      "say offset: when a literal offset reaches past the capacity" in {
          dstExtentOf("additive_past_end") shouldBe List("offset:const:8")
      }

      "stay unknown when the base itself has no extent" in {
          dstExtentOf("additive_unknown_base") shouldBe List("unknown")
      }

      "carry a param extent into offset: rather than inventing a number" in {
          dstExtentOf("additive_param_base") shouldBe List("offset:param:size")
      }

      "resolve memcpy(&dst, src, sizeof(dst)) through the copy's own sizeof" in {
          dstExtentOf("addressof_scalar_typed_by_copy") shouldBe List("sizeof:dst")
      }

      "keep the buffer's capacity for &buf[i]" in {
          dstExtentOf("addressof_index") shouldBe List("const:128")
      }

      "derive a pointer member's extent from the allocation assigned to it" in {
          val extent = dstExtentOf("member_from_alloc").head
          extent.startsWith("alloc:") shouldBe true
          val sizeNodeId = extent.stripPrefix("alloc:").toLong
          cpg.literal.code("256").l.map(_.id) should contain(sizeNodeId)
      }

      "derive a pointer member's extent as sizeof when the allocation size is one" in {
          dstExtentOf("member_from_alloc_sizeof") shouldBe List("sizeof:sizeof(struct two)")
      }

      "emit nothing for a member assigned from two allocations of different sizes" in {
          dstExtentOf("member_from_two_allocs") shouldBe List("unknown")
      }

      "tag the declaration the extent came from, so guards can match against it" in {
          cpg.local.name("buf").l.flatMap(_.tag.name("extent").value.l).distinct shouldBe List(
            "const:128"
          )
          cpg.method
              .name("param_row")
              .parameter
              .name("buf")
              .l
              .flatMap(_.tag.name("extent").value.l) shouldBe List("param:size")
          cpg.member.name("payload").l.flatMap(_.tag.name("extent").value.l) shouldBe List(
            "const:64"
          )
      }

      "emit the memory-safety umbrella alongside every extent tag" in {
          val extentNodes = cpg.tag.name("extent")._taggedByIn.l
          extentNodes should not be empty
          extentNodes.foreach { n =>
              n.tag.name.l should contain("memory-safety")
          }
      }
  }
end ExtentPassTests
