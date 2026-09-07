package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.Py2CpgTestContext
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

import scala.jdk.CollectionConverters.*

/** CPG shape for the soft keywords (match/case/type as identifiers). The code below used to fail to
  * parse - a parse error inside the parameter list of `probe` used to desynchronise the
  * INDENT/DEDENT stream and drop the entire enclosing function from the graph.
  */
class SoftKeywordCpgTests extends AnyFreeSpec with Matchers:

  private def unknownNodeCount(cpg: Cpg): Int =
      cpg.graph.nodes("UNKNOWN").asScala.size

  private lazy val cpg = Py2CpgTestContext.buildCpg(
    """import re
      |def probe(obj, case, s):
      |    a = re.match(r"x", s)
      |    b = obj.match(return_rule=True)
      |    c = obj.type
      |    d = obj.type()
      |    return a, b, c, d
      |class C:
      |    def match(self, x): return x
      |    def type(self): return 1
      |def g(case): return case
      |""".stripMargin
  )

  "soft keyword code parses without error statements" in {
      unknownNodeCount(cpg) shouldBe 0
  }

  "the enclosing method survives (no indent/dedent cascade)" in {
      cpg.method.name("probe").nonEmpty shouldBe true
      cpg.method.name("probe").parameter.name("case").nonEmpty shouldBe true
  }

  "re.match lowers to a call" in {
      cpg.call.name("match").code(".*re\\.match.*").nonEmpty shouldBe true
  }

  "obj.match and obj.type lower to attribute accesses" in {
      cpg.call.name("match").code(".*obj\\.match.*").nonEmpty shouldBe true
      cpg.call.name("type").code(".*obj\\.type.*").nonEmpty shouldBe true
  }

  "methods named match/type are defined" in {
      cpg.method.name("match").nonEmpty shouldBe true
      cpg.method.name("type").nonEmpty shouldBe true
  }

  "a parameter named case is a definition" in {
      cpg.method.name("g").parameter.name("case").nonEmpty shouldBe true
      cpg.identifier.name("case").nonEmpty shouldBe true
  }
end SoftKeywordCpgTests
