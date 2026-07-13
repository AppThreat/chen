package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** Evaluates free functions, the call graph across functions, CFG dominance, and the
  * data-dependence graph (DDG/PDG) via reachableBy on a numeric example.
  */
class CppFunctionsDataFlowTests extends CppDataFlowCodeToCpgSuite:

  private implicit val resolver: NoResolve.type = NoResolve

  private val cpg = code("""
      |#include <cstdio>
      |
      |int roll_dice(const int number_faces) {
      |    int random_int = number_faces * 2;
      |    return random_int;
      |}
      |
      |int main(int argc, char* argv[]) {
      |    int number_faces = 6;
      |    int number_rolls = 10;
      |    int sum = 0;
      |    int min_roll = 10000000;
      |    int max_roll = -10000000;
      |    for (int i = 0; i < number_rolls; i++) {
      |        int random_int = roll_dice(number_faces);
      |        sum += random_int;
      |        printf("You rolled a %d\n", random_int);
      |        if (random_int < min_roll) min_roll = random_int;
      |        if (random_int > max_roll) max_roll = random_int;
      |    }
      |    int average = sum / 10;
      |    printf("Your average roll was %d\n", average);
      |    return 0;
      |}
      |""".stripMargin)

  "AST: free function roll_dice" should {
      "have the correct signature, parameter and return type" in {
          val m = cpg.method.nameExact("roll_dice").head
          m.signature shouldBe "int (int)"
          m.parameter.name.l shouldBe List("number_faces")
          m.parameter.nameExact("number_faces").typeFullName.head shouldBe "int"
          m.methodReturn.typeFullName shouldBe "int"
      }

      "return the local random_int" in {
          cpg.method.nameExact("roll_dice").methodReturn.toReturn.astChildren.isIdentifier.name.l should contain(
            "random_int"
          )
      }
  }

  "Call graph across functions" should {
      "link the call site in main to roll_dice's definition" in {
          val call = cpg.method("main").call.nameExact("roll_dice").head
          call.methodFullName shouldBe "roll_dice:int(int)"
          call.callee.name.toSetMutable should contain("roll_dice")
      }

      "make main a caller of roll_dice" in {
          cpg.method.nameExact("roll_dice").caller.name.toSetMutable should contain("main")
      }

      "capture the printf call sites" in {
          cpg.call.nameExact("printf").size shouldBe 2
      }
  }

  "CFG: dominance inside the for loop" should {
      "make the min_roll assignment control-dependent on `random_int < min_roll`" in {
          cpg.assignment.code("min_roll = random_int").controlledBy.isCall.code.toSetMutable should contain(
            "random_int < min_roll"
          )
      }

      "have the loop guard dominate the loop body" in {
          val guard = cpg.method("main").controlStructure.condition.code("i < number_rolls").head
          guard.dominates.size should be > 0
      }
  }

  "DDG/PDG: data dependence" should {
      "flow from roll_dice's parameter into its return value" in {
          val src  = cpg.method("roll_dice").parameter.nameExact("number_faces")
          val sink = cpg.method("roll_dice").methodReturn
          sink.reachableBy(src).size should be > 0
      }

      "flow from number_faces in main into the argument of roll_dice" in {
          val src  = cpg.method("main").local.nameExact("number_faces").referencingIdentifiers
          val sink = cpg.method("main").call.nameExact("roll_dice").argument
          sink.reachableBy(src).size should be > 0
      }

      "flow from the roll_dice-assigned random_int into the printf argument" in {
          val src  = cpg.method("main").local.nameExact("random_int").referencingIdentifiers
          val sink = cpg.method("main").call.nameExact("printf").argument.isIdentifier.nameExact("random_int")
          sink.reachableByFlows(src).size should be > 0
      }

      "flow from sum into average via `sum / 10`" in {
          val src  = cpg.method("main").local.nameExact("sum").referencingIdentifiers
          val sink = cpg.method("main").call.nameExact("<operator>.assignment").code("average = .*").argument(2)
          sink.reachableBy(src).size should be > 0
      }
  }
end CppFunctionsDataFlowTests
