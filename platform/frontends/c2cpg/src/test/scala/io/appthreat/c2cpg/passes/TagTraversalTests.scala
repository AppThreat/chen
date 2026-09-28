package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.MemoryApiPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** TagTraversal.expression / .taggedNode: reading a tagged argument back generically.
  *
  * The memory-safety overlay tags the ARGUMENTS of memory-API calls, and those arguments are a mix
  * of node kinds - on FFmpeg's libavformat the `mem-len` tags come back as identifiers, calls and
  * literals. A detector written as `tag.name("mem-len").identifier` therefore silently misses every
  * tag that is not an identifier; `expression` is the step that does not.
  */
class TagTraversalTests extends CCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <string.h>
    |
    |void copy(char *src, int n) {
    |    char buf[64];
    |    memcpy(buf, src, n);
    |    snprintf(buf, sizeof(buf), "%s", src);
    |}
    |""".stripMargin,
    "probe.c"
  )

  new MemoryApiPass(cpg).createAndApply()

  // fresh traversals per assertion: the underlying Iterator[Tag] is consumed once
  private def memLen = cpg.tag.name("mem-len")

  "TagTraversal" should {

      "return tagged arguments of every kind through .expression" in {
          // memcpy's length is the identifier `n`, snprintf's is the call `sizeof(buf)`:
          // exactly one identifier argument and one call argument, two expressions.
          memLen.expression.l.size shouldBe 2
          memLen.identifier.l.size shouldBe 1
          memLen.call.l.size shouldBe 1
          memLen.expression.l.map(_.code).toSet shouldBe Set("n", "sizeof(buf)")
      }

      "return every tagged node through .taggedNode, narrowed by nothing" in {
          memLen.taggedNode.l.size shouldBe 2
          memLen.taggedNode.l.map(_.label).toSet shouldBe Set("IDENTIFIER", "CALL")
      }

      "return nothing from .expression when no tag matches" in {
          // every node the umbrella landed on in this fixture is an expression, so the two steps
          // agree; a tag family that landed only on non-expression nodes would differ by that many
          val umbrellaNodes = cpg.tag.name("memory-safety").taggedNode.l
          val umbrellaExprs = cpg.tag.name("memory-safety").expression.l
          umbrellaExprs.size shouldBe umbrellaNodes.size
          umbrellaNodes.size shouldBe 6
          cpg.tag.name("no-such-tag").expression.l.size shouldBe 0
      }
  }
end TagTraversalTests
