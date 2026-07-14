package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** Regression coverage for function-pointer variable declarations. A declarator such as
  * `int (*op)(int, int)` is an `IASTFunctionDeclarator` whose name binds to an `IVariable`, not an
  * `IFunction`. It used to be routed to the function-prototype path, whose `IVariable` branch
  * returned an empty Ast, so the whole declaration (LOCAL and initializer) was silently dropped.
  */
class CppFunctionPointerTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  "a local function pointer with an initializer" should {
      val cpg = code("""
          |int add(int a, int b) { return a + b; }
          |int useFp() {
          |    int (*op)(int, int) = add;
          |    int (*op2)(int, int);
          |    op2 = add;
          |    return op(1, 2) + op2(3, 4);
          |}
          |""".stripMargin)

      "create a LOCAL for the function-pointer variable (regression: was dropped)" in {
          cpg.method.nameExact("useFp").local.name.toSetMutable should contain allOf ("op", "op2")
      }

      "create the initializer assignment (regression: was dropped)" in {
          val assignedTo = cpg.method
              .nameExact("useFp")
              .call
              .nameExact(Operators.assignment)
              .argument(1)
              .isIdentifier
              .name
              .toSetMutable
          assignedTo should contain("op")
      }

      "invoke the function pointer through the pointer-call operator" in {
          cpg.method.nameExact("useFp").call.nameExact("<operator>.pointerCall").l should not be empty
      }
  }

  "a global function-pointer variable" should {
      val cpg = code("""
          |int add(int a, int b) { return a + b; }
          |int (*globalOp)(int, int) = add;
          |""".stripMargin)

      "be created as a LOCAL/identifier rather than a spurious method" in {
          cpg.method.nameExact("globalOp").l shouldBe empty
          cpg.local.nameExact("globalOp").l should not be empty
      }
  }
end CppFunctionPointerTests
