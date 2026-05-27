package io.appthreat.jimple2cpg.testfixtures

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.dataflowengineoss.semanticsloader.FlowSemantic
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

class JimpleDataflowTestCpg(val extraFlows: List[FlowSemantic] = List.empty) extends JimpleTestCpg {

  implicit val resolver: ICallResolver           = NoResolve
  implicit lazy val engineContext: EngineContext = EngineContext()

  override def applyPasses(): Unit = {
    super.applyPasses()
    val context = new LayerCreatorContext(this)
    val options = new OssDataFlowOptions(extraFlows = extraFlows)
    new OssDataFlow(options).run(context)
  }

}

class JimpleDataFlowCodeToCpgSuite(val extraFlows: List[FlowSemantic] = List.empty)
    extends Code2CpgFixture(() => new JimpleDataflowTestCpg(extraFlows)) {

  implicit var context: EngineContext = EngineContext()

  def getConstSourceSink(methodName: String, sourceCode: String = "\"MALICIOUS\"", sinkPattern: String = ".*println.*")(
    implicit cpg: Cpg
  ): (Iterator[Literal], Iterator[Expression]) = {
    getMultiFnSourceSink(methodName, methodName, sourceCode, sinkPattern)
  }

  def getMultiFnSourceSink(
    sourceMethodName: String,
    sinkMethodName: String,
    sourceCode: String = "\"MALICIOUS\"",
    sinkPattern: String = ".*println.*"
  )(implicit cpg: Cpg): (Iterator[Literal], Iterator[Expression]) = {
    val sourceMethod = cpg.method(s".*$sourceMethodName").head
    val sinkMethod   = cpg.method(s".*$sinkMethodName").head

    def normalizeLiteralCode(code: String): String =
      code.stripPrefix("\"").stripSuffix("\"")

    def source = {
      val allLiterals = sourceMethod.literal.l
      val isRegexLike = sourceCode.exists(ch => "*+?[](){}|.^$\\".contains(ch))

      val matched =
        if (isRegexLike) {
          val sourceRegex = sourceCode.r
          allLiterals.filter(l => sourceRegex.findFirstIn(l.code).nonEmpty)
        } else {
          val normalizedSource = normalizeLiteralCode(sourceCode)
          allLiterals.filter { lit =>
            lit.code == sourceCode || normalizeLiteralCode(lit.code) == normalizedSource
          }
        }

      matched.iterator
    }

    def sink = sinkMethod.call.name(sinkPattern).argument(1).ast.collectAll[Expression]

    // If either of these fail, then the testcase was written incorrectly or the AST was created incorrectly.
    if (sink.size <= 0) {
      fail(s"Could not find sink $sinkPattern for method $sinkMethodName")
    }

    (source, sink)
  }
}
