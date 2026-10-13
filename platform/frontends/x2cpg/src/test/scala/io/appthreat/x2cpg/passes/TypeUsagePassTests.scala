package io.appthreat.x2cpg.passes

import io.appthreat.x2cpg.passes.base.TypeUsagePass
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, PropertyNames}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** A C struct declared in a header (`typedef struct s S;`) and defined in a source file gives two
  * type declarations with one full name, in whichever order a parallel frontend wrote the files.
  */
class TypeUsagePassTests extends AnyWordSpec with Matchers:

  private def graph(definitionFirst: Boolean) =
    val cpg = MockCpg().withCustom { (graph, _) =>
      val forward = NewTypeDecl().name("s").fullName("s").filename("include/s.h").lineNumber(3)
          .code("typedef struct s").aliasTypeFullName("S")
      val definition = NewTypeDecl().name("s").fullName("s").filename("src/s.c").lineNumber(10)
          .code("struct s { ... }")
      val member = NewMember().name("buf").typeFullName("int[3]")
      val decls  = if definitionFirst then Seq(definition, forward) else Seq(forward, definition)
      decls.foreach(graph.addNode)
      graph.addNode(member)
      graph.addEdge(definition, member, EdgeTypes.AST)
      graph.addNode(NewType().name("s").fullName("s").typeDeclFullName("s"))
    }.cpg
    // as the base layer does before it links
    cpg.graph.indexManager.createNodePropertyIndex(PropertyNames.FULL_NAME)
    new TypeUsagePass(cpg).createAndApply()
    cpg

  "TypeUsagePass" should {
      "link a type to the same declaration of several, the definition, in either order" in {
          Seq(true, false).foreach { definitionFirst =>
              withClue(s"definition written first: $definitionFirst") {
                  val cpg = graph(definitionFirst)
                  cpg.typ.fullNameExact("s").referencedTypeDecl.filename.l shouldBe List("src/s.c")
              }
          }
      }
  }
end TypeUsagePassTests
