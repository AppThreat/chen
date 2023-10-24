package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.Py2CpgTestContext
import io.shiftleft.semanticcpg.language._
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

class ModuleFunctionCpgTests extends AnyFreeSpec with Matchers {
  lazy val cpg = Py2CpgTestContext.buildCpg("""pass""".stripMargin)

  "test module method node properties" in {
    val methodNode = cpg.method.fullName("test").head
    methodNode.name shouldBe "test"
    methodNode.fullName shouldBe "test"
    methodNode.lineNumber shouldBe Some(1)
  }

  "test method body" in {
    val topLevelExprs = cpg.method.fullName("test").topLevelExpressions.l
    topLevelExprs.size shouldBe 1
    topLevelExprs.isCall.head.code shouldBe "pass"
    topLevelExprs.isCall.head.methodFullName shouldBe "<operator>.pass"
  }
}
