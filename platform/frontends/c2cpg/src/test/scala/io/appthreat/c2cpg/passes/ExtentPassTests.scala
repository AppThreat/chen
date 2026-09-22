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

      "tag the declaration the extent came from, so guards can match against it" in {
          cpg.local.name("buf").l.flatMap(_.tag.name("extent").value.l) shouldBe List("const:128")
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
              n match
                case s: io.shiftleft.codepropertygraph.generated.nodes.StoredNode =>
                    s.tag.name.l should contain("memory-safety")
                case _ => fail("extent tags only land on stored nodes")
          }
      }
  }
end ExtentPassTests
