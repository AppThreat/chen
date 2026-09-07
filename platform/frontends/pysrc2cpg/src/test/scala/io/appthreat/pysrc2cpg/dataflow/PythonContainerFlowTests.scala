package io.appthreat.pysrc2cpg.dataflow

import io.appthreat.dataflowengineoss.language.toExtendedCfgNode
import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Task 5 / item 3: container element typing must carry taint through iteration and subscripts, not
  * only produce pretty TYPE_FULL_NAMEs.
  */
class PythonContainerFlowTests extends PySrc2CpgFixture(withOssDataflow = true):

  "taint through iteration over an annotated list" should:
    "reach the sink inside the loop body" in:
      val cpg = code(
        """
            |import helpers
            |def handle(items: list[str]) -> None:
            |    for x in items:
            |        helpers.sink(x)
            |""".stripMargin,
        "forflow.py"
      )
      val source = cpg.parameter.name("items")
      val sink   = cpg.call.name("sink").argument
      sink.reachableByFlows(source).size should be >= 1

  "taint through subscript of an annotated dict" should:
    "reach the sink" in:
      val cpg = code(
        """
            |import helpers
            |def handle(mapping: dict[str, str], key: str) -> None:
            |    value = mapping[key]
            |    helpers.sink(value)
            |""".stripMargin,
        "indexflow.py"
      )
      val source = cpg.parameter.name("mapping")
      val sink   = cpg.call.name("sink").argument
      sink.reachableByFlows(source).size should be >= 1

  // Recorded, not asserted: `name = spec["table"][-1]; sink(name)` finds no flow at HEAD
  // either - the dataflow engine loses taint across chained indexAccess operator calls
  // (pre-existing, reproduced with a clean tree). The *typing* half of this shape is
  // asserted in PythonTypeInferenceTests.
end PythonContainerFlowTests
