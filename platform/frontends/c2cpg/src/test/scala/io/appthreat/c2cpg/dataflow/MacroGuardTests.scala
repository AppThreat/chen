package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.{DataFlowCodeToCpgSuite, DataFlowTestCpg}
import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn
import io.shiftleft.semanticcpg.language.*

/** Macro guards must be visible to data flow.
  *
  * In C, guards are written as macros (`FFMIN`, `FFMAX`, `av_clip`). The frontend emits a macro
  * invocation as a synthetic INLINED call plus a copy of the expansion under a wrapper block, and
  * `cfgForInlinedCall` is what wires that copy into the method's CFG. If the copy is ever left
  * detached again (the defect this suite guards against), every guard written as a macro becomes
  * invisible: no CFG edges, no reaching definitions, and a bounds detector would report every
  * correctly clamped copy as a finding.
  *
  * The macro is deliberately defined in a HEADER: same-translation-unit macros do not exercise the
  * synthetic-call path the way a foreign-file macro does (the FFmpeg `FFMIN` shape).
  */
class MacroGuardTests extends DataFlowCodeToCpgSuite:

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
        |int read_block(unsigned char *buf, int payload_len, int size) {
        |    size = FFMIN(payload_len, size);
        |    memcpy(buf, 0, size);
        |    return size;
        |}
        |""".stripMargin,
        "probe.c"
      )

  private def ffminCall = cpg.call.name("FFMIN").head

  "a header-defined clamping macro" should {

      "be emitted as an INLINED call with a location-encoded fullName" in {
          val call = ffminCall
          call.dispatchType shouldBe DispatchTypes.INLINED
          // path/to/clamps.h:<line>:<line>:FFMIN:<argc> - the shape the clamping-macro
          // semantics are keyed on.
          (call.methodFullName should fullyMatch).regex(".*:FFMIN:\\d+$")
      }

      "have its expansion wired into the method CFG" in {
          val expansionEntry = ffminCall.astChildren.isBlock.head.astChildren.l
          expansionEntry should not be empty

          // The expansion's entry must be reachable by a CFG edge from the macro call
          // (cfgForInlinedCall): a subtree with only internal edges is detached, which is the
          // defect this guards against.
          val callSuccessors = ffminCall.cfgNext.l.map(_.id).toSet
          val expansionIds   = ffminCall.astChildren.isBlock.head.ast.isCfgNode.id.toSet
          callSuccessors.intersect(expansionIds) should not be empty

          // ... and every CFG node of the expansion is connected (non-zero degree), so reaching
          // definitions can flow into it. The wrapper BLOCK itself is deliberately not a CFG
          // node (cfgFor skips blocks under inlined calls), so it is excluded.
          ffminCall.astChildren.isBlock.head.ast.isCfgNode.l
              .filterNot(_.isBlock)
              .foreach { n =>
                  (n._cfgIn.l.size + n._cfgOut.l.size) should be > 0
              }
      }

      "receive real reaching definitions inside the expansion" in {
          // The def chain a bounds rule reads: PARAMETER defines the macro call's argument
          // nodes, and the argument definitions flow on into the expansion copy. A detached
          // expansion falls back to method-entry edges only - neither link exists there.
          val argDefs = ffminCall.argument.isIdentifier.l.flatMap { i =>
              i._reachingDefIn.l.collect { case p: MethodParameterIn => p.name }
          }
          argDefs should contain("size")
          argDefs should contain("payload_len")

          val argIds = ffminCall.argument.isIdentifier.id.l.toSet
          argIds should not be empty
          val expansionDefIds = ffminCall.astChildren.isBlock.head.ast.isIdentifier.l
              .flatMap(_._reachingDefIn.l.map(_.id))
          expansionDefIds.toSet.intersect(argIds) should not be empty
      }

      "carry the clamp through to the guarded write" in {
          // The part-2 shape: both FFMIN arguments reach the memcpy length, THROUGH the macro
          // call. Before the macro call was given argument children, the data-flow chain stopped
          // at the call boundary (nothing could taint its value), and a size-parameter rule
          // fired on correctly clamped code.
          val sink   = cpg.call.name("memcpy").head.argument(3).start
          val source = cpg.method.name("read_block").parameter
          val flows  = sink.reachableByFlows(source).l
          flows should not be empty
          // both parameters cross the macro boundary
          val startCodes = flows.flatMap(_.elements).l.map(_.code)
          startCodes should contain("payload_len")
          startCodes should contain("size")
      }

      "match the clamping-macro semantics despite the location-encoded fullName" in {
          // The regex entries in DefaultSemantics.clampingMacroFlows are keyed on the
          // `file:line:lineEnd:NAME:argc` encoding; this pins that they actually match what the
          // frontend emits.
          val semantics = DefaultSemantics.cSemantics()
          semantics.loadRegexSemantics(cpg)
          cpg.call.name("FFMIN").l.foreach { call =>
              semantics.forMethod(call.methodFullName) should not be None
          }
          cpg.call.name("FFMAX").l.foreach { call =>
              semantics.forMethod(call.methodFullName) should not be None
          }
      }
  }
end MacroGuardTests
