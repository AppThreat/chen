package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A `const` integral from a header the tree does not parse reads as its compile-time value, the
  * way a `#define` already does: leveldb's `level < config::kNumLevels` bounds every caller of an
  * index into `files_[config::kNumLevels]`.
  */
class HeaderConstantTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |static const int kLevels = 7;
    |static const int kTooMany = 8;
    |struct version { int files[7]; };
    |""".stripMargin,
    "levels.inc"
  ).moreCode(
    """
    |#include "levels.inc"
    |static void add_file(struct version *v, int level) { v->files[level] = 1; }
    |void save_to(struct version *v)
    |{
    |    for (int level = 0; level < kLevels; level++)
    |        add_file(v, level);
    |}
    |static void add_file_too_many(struct version *v, int level) { v->files[level] = 1; }
    |void save_too_many(struct version *v)
    |{
    |    for (int level = 0; level < kTooMany; level++)
    |        add_file_too_many(v, level);
    |}
    |""".stripMargin,
    "version.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def boundFindings(method: String): List[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l).filter(_.startsWith("MS-BOUND")).l

  "a header constant" should:
    "carry its value on the identifiers that read it" in {
        cpg.identifier.nameExact("kLevels").tag.name(io.appthreat.x2cpg.Defines.ConstValueTag)
            .value.l.distinct shouldBe List("7")
    }
    "bound every caller's index by its value" in {
        boundFindings("add_file") shouldBe empty
    }
    "not bound an index past the extent" in {
        boundFindings("add_file_too_many") should not be empty
    }
end HeaderConstantTests
