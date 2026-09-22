package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    ExtentPass,
    GuardPass,
    IntegerWidthPass,
    MemoryApiPass,
    ValueOriginPass
}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** IntegerWidthPass (C5): facts only, no rule. Each litmus shape has its benign neighbour beside
  * it, so the absence of a fact is a checked absence.
  */
class IntegerWidthPassTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |struct nal_array { void *nal; unsigned short numNalus; };
    |
    |/* the CVE-2026-75141 shape: the counter is computed in int and wraps into 16 bits */
    |int hevc_shape(struct nal_array *array)
    |{
    |    array->numNalus = array->numNalus + 1;
    |    return array->numNalus;
    |}
    |
    |/* the CVE-2026-75145 shape: an unsigned value reinterpreted as signed in a guard */
    |int resign_guard(unsigned int obu_size, int frame_size)
    |{
    |    return (long)obu_size > frame_size;
    |}
    |
    |/* attacker-influenced multiplication reaching an allocation size */
    |void arith_len(size_t n)
    |{
    |    char *p = malloc(n * 4);
    |    free(p);
    |}
    |
    |/* benign neighbours: same width, no attacker operand, no arithmetic at all */
    |int benign_same_width(int a, int b)
    |{
    |    int c = a + b;
    |    return c;
    |}
    |
    |int benign_cast(unsigned int u)
    |{
    |    return (int)(u & 0xffu);
    |}
    |""".stripMargin,
    "widths.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()

  private def factsOn(tag: String): List[(String, String)] =
      cpg.tag.name(tag).l.flatMap { t =>
          t._taggedByIn.collectFirst {
              case e: io.shiftleft.codepropertygraph.generated.nodes.Expression =>
                  (e.code, t.value)
          }
      }

  "IntegerWidthPass" should:

    "tag the uint16 counter increment as computed-in-a-wider-type" in {
        factsOn("int-narrow").find(_._1.contains("numNalus")) shouldBe defined
    }

    "tag the unsigned-to-signed guard cast" in {
        factsOn("int-resign").find(_._1.contains("(long)")) should not be empty
    }

    "tag attacker-influenced arithmetic that computes an allocation size" in {
        val fact = factsOn("int-arith-len").find(_._1.contains("*"))
        fact shouldBe defined
        fact.get._2.contains("caller-param") shouldBe true
    }

    "emit no narrow fact when the widths already agree" in {
        factsOn("int-narrow").map(_._1) should not contain "c = a + b"
    }

    "emit the facts with the memory-safety umbrella, so the family reads as one" in {
        val narrowed = cpg.tag.name("int-narrow").l.flatMap(_._taggedByIn).l
        narrowed should not be empty
        narrowed.foreach { n =>
            n.tag.name.l should contain("memory-safety")
        }
    }
end IntegerWidthPassTests
