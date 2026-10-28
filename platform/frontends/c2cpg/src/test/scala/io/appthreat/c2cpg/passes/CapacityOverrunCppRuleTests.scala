package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.C2CpgFrontend
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.taggers.*
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, TestCpg}
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

class DataFlowCppTestCpg extends TestCpg with C2CpgFrontend:
  override val fileSuffix: String = FileDefaults.CPP_EXT

  override protected def applyPasses(): Unit =
    X2Cpg.applyDefaultOverlays(this)
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(this))

/** MS-BOUND-006 over a placement new: the constructed class's size, read off the members the
  * frontends size, measures the buffer the placement constructs into - the declared-array buffer
  * shorter than the class overruns at the members the extra bytes reach.
  */
class CapacityOverrunCppRuleTests extends Code2CpgFixture(() => new DataFlowCppTestCpg()):

  private val cpg = code(
    """
      |#include <cstddef>
      |#include <cstdlib>
      |
      |class TwoIntsClass { public: int intOne; int intTwo; };
      |class OneIntClass { public: int intOne; };
      |
      |void bad_placement_declare(void)
      |{
      |    char *data;
      |    char dataBadBuffer[sizeof(OneIntClass)];
      |    char dataGoodBuffer[sizeof(TwoIntsClass)];
      |    data = dataBadBuffer;
      |    TwoIntsClass *classTwo = new(data) TwoIntsClass;
      |    classTwo->intOne = 5;
      |    classTwo->intTwo = 10;
      |}
      |
      |void good_placement_declare_right(void)
      |{
      |    char *data;
      |    char dataBadBuffer[sizeof(OneIntClass)];
      |    char dataGoodBuffer[sizeof(TwoIntsClass)];
      |    data = dataGoodBuffer;
      |    TwoIntsClass *classTwo = new(data) TwoIntsClass;
      |    classTwo->intOne = 5;
      |    classTwo->intTwo = 10;
      |}
      |
      |void good_placement_smaller_class(void)
      |{
      |    char *data;
      |    char dataBadBuffer[sizeof(OneIntClass)];
      |    char dataGoodBuffer[sizeof(TwoIntsClass)];
      |    data = dataBadBuffer;
      |    OneIntClass *classOne = new(data) OneIntClass;
      |    classOne->intOne = 5;
      |}
      |
      |#include <alloca.h>
      |#define ALLOCA alloca
      |
      |void bad_placement_alloca(void)
      |{
      |    char *data;
      |    char *dataBadBuffer = (char *)ALLOCA(sizeof(OneIntClass));
      |    char *dataGoodBuffer = (char *)ALLOCA(sizeof(TwoIntsClass));
      |    data = dataBadBuffer;
      |    TwoIntsClass *classTwo = new(data) TwoIntsClass;
      |    classTwo->intOne = 5;
      |    classTwo->intTwo = 10;
      |}
      |
      |void good_placement_alloca_right(void)
      |{
      |    char *data;
      |    char *dataBadBuffer = (char *)ALLOCA(sizeof(OneIntClass));
      |    char *dataGoodBuffer = (char *)ALLOCA(sizeof(TwoIntsClass));
      |    data = dataGoodBuffer;
      |    TwoIntsClass *classTwo = new(data) TwoIntsClass;
      |    classTwo->intOne = 5;
      |    classTwo->intTwo = 10;
      |}
      |
      |void good_placement_alloca_smaller_class(void)
      |{
      |    char *data;
      |    char *dataBadBuffer = (char *)ALLOCA(sizeof(OneIntClass));
      |    char *dataGoodBuffer = (char *)ALLOCA(sizeof(TwoIntsClass));
      |    data = dataBadBuffer;
      |    OneIntClass *classOne = new(data) OneIntClass;
      |    classOne->intOne = 5;
      |}
    """.stripMargin,
    "placement.cpp"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "a placement new of a class larger than its buffer" should:
    "overrun a declared buffer shorter than the constructed class" in {
        findingsIn("bad_placement_declare") should contain("MS-BOUND-006")
    }
    "stay quiet when the declared buffer holds the class" in {
        findingsIn("good_placement_declare_right") should not contain "MS-BOUND-006"
    }
    "stay quiet when the constructed class fits the short buffer" in {
        findingsIn("good_placement_smaller_class") should not contain "MS-BOUND-006"
    }
    "overrun an alloca sized by a smaller class" in {
        findingsIn("bad_placement_alloca") should contain("MS-BOUND-006")
    }
    "stay quiet when the alloca was sized by the constructed class" in {
        findingsIn("good_placement_alloca_right") should not contain "MS-BOUND-006"
        findingsIn("good_placement_alloca_smaller_class") should not contain "MS-BOUND-006"
    }
end CapacityOverrunCppRuleTests
