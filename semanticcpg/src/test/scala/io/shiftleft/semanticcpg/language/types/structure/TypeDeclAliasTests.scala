package io.shiftleft.semanticcpg.language.types.structure

import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** A C struct declared in a header (`typedef struct s S;`) and defined in a source file: the type
  * `s` has two declarations, and which one the graph stores first depends on the order a parallel
  * frontend wrote the files in.
  */
class TypeDeclAliasTests extends AnyWordSpec with Matchers:

  /** The header's forward declaration of `s` is written as an alias of the typedef, as the C
    * frontend writes it, so following aliases from either name can cycle back.
    */
  private def headerAndDefinition(definitionFirst: Boolean, secondDefinition: Boolean = false) =
      MockCpg().withCustom { (graph, _) =>
        val typeS = NewType().name("s").fullName("s").typeDeclFullName("s")
        val typeT = NewType().name("S").fullName("S").typeDeclFullName("S")
        val forward = NewTypeDecl().name("s").fullName("s").filename("include/s.h").lineNumber(3)
            .code("typedef struct s").aliasTypeFullName("S")
        val typedef = NewTypeDecl().name("S").fullName("S").filename("include/s.h").lineNumber(3)
            .code("typedef struct s S;").aliasTypeFullName("s")
        def definition(file: String, member: String) =
          val decl = NewTypeDecl().name("s").fullName("s").filename(file).lineNumber(10)
              .code("struct s { ... }")
          val m = NewMember().name(member).typeFullName("int[3]")
          graph.addNode(decl)
          graph.addNode(m)
          graph.addEdge(decl, m, EdgeTypes.AST)
          decl
        Seq(typeS, typeT, forward, typedef).foreach(graph.addNode)
        val defs =
            Seq(definition("src/b.c", "from_b")) ++
                Option.when(secondDefinition)(definition("src/a.c", "from_a"))
        val refs = if definitionFirst then defs :+ forward else forward +: defs
        refs.foreach(d => graph.addEdge(typeS, d, EdgeTypes.REF))
        graph.addEdge(typeT, typedef, EdgeTypes.REF)
        graph.addEdge(typedef, typeS, EdgeTypes.ALIAS_OF)
        graph.addEdge(forward, typeT, EdgeTypes.ALIAS_OF)
      }.cpg

  "A typedef of a struct defined elsewhere" should {
      "reach the definition's members whichever declaration the graph stored first" in {
          Seq(true, false).foreach { definitionFirst =>
              withClue(s"definition stored first: $definitionFirst") {
                  val cpg = headerAndDefinition(definitionFirst)
                  cpg.typeDecl.nameExact("S").member.name.l shouldBe List("from_b")
                  cpg.typeDecl.nameExact("s").filenameExact("include/s.h").member.name.l shouldBe
                      List("from_b")
              }
          }
      }

      "pick the same definition every time when two files define the struct" in {
          Seq(true, false).foreach { definitionFirst =>
              withClue(s"definitions stored first: $definitionFirst") {
                  headerAndDefinition(definitionFirst, secondDefinition = true)
                      .typeDecl.nameExact("S").member.name.l shouldBe List("from_a")
              }
          }
      }
  }
end TypeDeclAliasTests
