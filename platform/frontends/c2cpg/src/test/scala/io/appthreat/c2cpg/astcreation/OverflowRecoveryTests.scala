package io.appthreat.c2cpg.astcreation

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{CdtParser, HeaderFileFinder}
import io.appthreat.x2cpg.datastructures.Stack.*
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.nodes.{NewBlock, NewLocal, NewUnknown}
import org.eclipse.cdt.core.dom.ast.IASTTranslationUnit
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap

/** A construct whose AST CDT overflows the stack on: the construct is lost, the file is not. */
class OverflowRecoveryTests extends AnyWordSpec with Matchers:

  private class Probe(file: String, unit: IASTTranslationUnit)
      extends AstCreator(file, Config(), unit, new ConcurrentHashMap[String, Array[Int]]())(using
        ValidationMode.Disabled
      ):
    /** Overflows after pushing a scope, declaring a variable and pushing an AST parent. */
    def overflowWhileBuilding(): (Ast, Boolean, Boolean, Boolean) =
      val scopes  = scope.snapshot
      val parents = methodAstParentStack.size
      val ast = withOverflowRecovery(unit.getDeclarations.head, identity) {
          scope.pushNewScope(NewBlock())
          scope.addToScope("leaked", (NewLocal().name("leaked"), "int"))
          methodAstParentStack.push(NewBlock())
          throw new StackOverflowError()
      }
      (
        ast,
        scope.snapshot == scopes,
        methodAstParentStack.size == parents,
        scope.lookupVariable("leaked").isEmpty
      )
  end Probe

  "an overflow while a construct's AST is built" should {
      val file = Files.createTempFile("overflow", ".c")
      Files.writeString(file, "int answer(void) { return 42; }\n")
      file.toFile.deleteOnExit()
      val unit = new CdtParser(Config(), new HeaderFileFinder("")).parse(file).get

      "leave an UNKNOWN node with the construct's code, and put the scopes and parents back" in {
          val (ast, scopesBack, parentsBack, variableGone) =
              new Probe(file.toString, unit).overflowWhileBuilding()
          ast.root.collect { case u: NewUnknown => u.code } shouldBe
              Some("int answer(void) { return 42; }")
          scopesBack shouldBe true
          parentsBack shouldBe true
          variableGone shouldBe true
      }
  }
end OverflowRecoveryTests
