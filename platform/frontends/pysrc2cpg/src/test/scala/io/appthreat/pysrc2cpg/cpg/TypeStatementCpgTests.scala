package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.Py2CpgTestContext
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

import scala.jdk.CollectionConverters.*

/** PEP 695 `type` alias statements must reach the CPG as a TYPE_DECL plus an alias binding - not as
  * a dropped/ErrorStatement node.
  */
class TypeStatementCpgTests extends AnyFreeSpec with Matchers:

  private def unknownNodeCount(cpg: Cpg): Int =
      cpg.graph.nodes("UNKNOWN").asScala.size

  private lazy val cpg = Py2CpgTestContext.buildCpg(
    """type Alias[T] = list[T]
      |type Point = tuple[float, float]
      |type ListOrSet[T = int] = list[T] | set[T]
      |x = 1
      |""".stripMargin
  )

  private lazy val oneLinerCpg = Py2CpgTestContext.buildCpg(
    """def f():
      |    type Inner = int
      |    return Inner
      |""".stripMargin
  )

  "type aliases produce TYPE_DECL nodes" in {
      cpg.typeDecl.name("Alias").nonEmpty shouldBe true
      cpg.typeDecl.name("Point").nonEmpty shouldBe true
      cpg.typeDecl.name("ListOrSet").nonEmpty shouldBe true
  }

  "the alias name is bound by an assignment" in {
      cpg.identifier.name("Alias").nonEmpty shouldBe true
      cpg.identifier.name("ListOrSet").nonEmpty shouldBe true
  }

  "no statement is lost to a parse error" in {
      unknownNodeCount(cpg) shouldBe 0
      cpg.local.name("x").nonEmpty shouldBe true
  }

  "type aliases inside a nested block parse" in {
      unknownNodeCount(oneLinerCpg) shouldBe 0
      oneLinerCpg.typeDecl.name("Inner").nonEmpty shouldBe true
  }
end TypeStatementCpgTests
