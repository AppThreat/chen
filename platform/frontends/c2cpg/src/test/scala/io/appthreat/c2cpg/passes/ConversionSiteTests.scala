package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.semanticcpg.language.*

/** Every place C converts a value implicitly carries the conversion's facts, judged the way a
  * compiler warns: a narrower destination narrows, a constant by its value, a bit pattern only by
  * the bits it loses.
  */
class ConversionSiteTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stddef.h>
    |void take_short(short s);
    |void take_uchar(unsigned char c);
    |void take_any(int n, ...);
    |
    |short ret_narrow(int v) { return v; }
    |unsigned char ret_fits(void) { return 200; }
    |unsigned char ret_over(void) { return 300; }
    |int ret_same(int v) { return v; }
    |
    |void stores(int i, long l, size_t z)
    |{
    |    unsigned char init_narrow = i;
    |    short init_long = l;
    |    int from_size = z;
    |    unsigned char fits = 255;
    |    unsigned char hex_fits = 0xFF;
    |    unsigned char over = 300;
    |    unsigned char hex_over = 0x1FF;
    |    signed char hex_sign = 0x80;
    |    unsigned neg = -1;
    |    unsigned hex_neg = ~0;
    |    long widen = i;
    |}
    |
    |void arguments(int i, unsigned char c)
    |{
    |    take_short(i);
    |    take_uchar(i);
    |    take_uchar(c);
    |    take_uchar(7);
    |    take_any(1, i);
    |}
    |
    |int comparisons(int i, unsigned u, unsigned short us, long l)
    |{
    |    int a = i < u;
    |    int b = i < us;
    |    int c = l < u;
    |    return a + b + c;
    |}
    |""".stripMargin,
    "sites.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()

  private def factsOn(method: String, tag: String): List[String] =
      cpg.method.nameExact(method).ast.flatMap(n => n.tag.nameExact(tag).value.map(n.code -> _))
          .l.map((code, value) => s"$code => $value")

  private def narrowed(method: String): List[String] =
      factsOn(method, IntegerWidthPass.TagNarrow).map(_.split(" => ").head)

  private def resigned(method: String): List[String] =
      factsOn(method, IntegerWidthPass.TagResign).map(_.split(" => ").head)

  "a return" should {
      "narrow into a narrower return type" in {
          narrowed("ret_narrow") shouldBe List("return v;")
      }
      "judge a returned constant by its value" in {
          narrowed("ret_fits") shouldBe empty
          narrowed("ret_over") shouldBe List("return 300;")
      }
      "not narrow at the same width" in {
          narrowed("ret_same") shouldBe empty
      }
  }

  "a store" should {
      "narrow a wider value" in {
          (narrowed("stores") should contain).allOf(
            "init_narrow = i",
            "init_long = l",
            "from_size = z"
          )
      }
      "judge a decimal constant by its value" in {
          narrowed("stores") should contain("over = 300")
          narrowed("stores") should not contain "fits = 255"
          resigned("stores") should contain("neg = -1")
      }
      "judge a bit pattern only by the bits it loses" in {
          narrowed("stores") should contain("hex_over = 0x1FF")
          narrowed("stores") should not contain "hex_fits = 0xFF"
          narrowed("stores") should not contain "hex_sign = 0x80"
          resigned("stores") should not contain "hex_neg = ~0"
      }
      "not narrow when widening" in {
          narrowed("stores") should not contain "widen = i"
      }
  }

  "an argument" should {
      "narrow into a narrower parameter" in {
          factsOn("arguments", IntegerWidthPass.TagNarrow).filter(_.contains("arg:1:")).map(
            _.split(" => ").head
          ) shouldBe List("i", "i")
      }
      "not narrow at the parameter's width, for a fitting constant, or through varargs" in {
          narrowed("arguments").count(_ == "i") shouldBe 2
          narrowed("arguments") should not contain "c"
          narrowed("arguments") should not contain "7"
      }
  }

  "a comparison" should {
      "change the sign of a signed operand compared with an unsigned one as wide" in {
          // `i < us` promotes to int and `l < u` converts u to long: neither changes a sign
          resigned("comparisons") shouldBe List("i < u")
      }
  }
end ConversionSiteTests
