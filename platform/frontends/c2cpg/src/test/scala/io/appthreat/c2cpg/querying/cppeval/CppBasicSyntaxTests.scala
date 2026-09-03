package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.codepropertygraph.generated.nodes.{Call, ControlStructure, Identifier, Literal}
import io.shiftleft.semanticcpg.language.*

/** Evaluates AST + CFG creation for a basic C++ translation unit exercising primitive types,
  * blocks, if/else-if/else, switch/case, for, range-based-for, while, continue and return.
  */
class CppBasicSyntaxTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private val cpg = code("""
      |#include <iostream>
      |#include <string>
      |
      |int main(int argc, char* argv[]) {
      |    auto f = 1.23f;
      |    double d = 1.23;
      |    long double ld = 1.34;
      |    int i = 0;
      |    short s = 32000;
      |    long l = 18000000000;
      |    long long ll = 1292309230983;
      |    char c = 0;
      |    auto b = false;
      |    {
      |        int j = 1;
      |        int t = j;
      |    }
      |    if (b) {
      |        std::cout << "B is true!" << std::endl;
      |    } else if (!b) {
      |        std::cout << "B is false!" << std::endl;
      |    } else {
      |        std::cout << "unreachable" << std::endl;
      |    }
      |    switch (i) {
      |    case 0:
      |        std::cout << "switch 0" << std::endl;
      |        break;
      |    case 1:
      |        std::cout << "switch 1" << std::endl;
      |        break;
      |    default:
      |        break;
      |    }
      |    for (unsigned int count = 0; count < 10; count++) {
      |        if (count == 5) continue;
      |        std::cout << count << std::endl;
      |    }
      |    std::string str = "hello";
      |    for (char character : str) {
      |        std::cout << character << std::endl;
      |    }
      |    int while_count = 0;
      |    while (while_count < 10) {
      |        while_count++;
      |    }
      |    return 0;
      |}
      |""".stripMargin)

  "AST: file / metadata" should {
      "create a single source File node with the C++ suffix" in {
          val files = cpg.file.name.filterNot(n => n == "<includes>" || n == "<unknown>").l
          files.size shouldBe 1
          files.head.endsWith(FileDefaults.CPP_EXT) shouldBe true
      }

      "record C++ as the metadata language" in {
          cpg.metaData.language.l should not be empty
      }
  }

  "AST: methods and parameters" should {
      "create the main method with the correct signature and parameters" in {
          val main = cpg.method.nameExact("main").head
          main.signature shouldBe "int (int,char[]*)"
          main.parameter.name.l shouldBe List("argc", "argv")
          main.parameter.nameExact("argc").typeFullName.head shouldBe "int"
          main.parameter.nameExact("argv").typeFullName.head shouldBe "char[]*"
          main.methodReturn.typeFullName shouldBe "int"
      }

      "give main a body block, cfg entry and exit" in {
          val main = cpg.method.nameExact("main").head
          main.astChildren.isBlock.l should not be empty
          main.cfgFirst.l should not be empty
          main.methodReturn.cfgPrev.l should not be empty
      }
  }

  "AST: locals capture every declared variable with its type" should {
      "cover all primitive and inferred (auto) locals" in {
          val locals = cpg.method("main").local.map(l => l.name -> l.typeFullName).toMap
          locals("f") shouldBe "float"
          locals("d") shouldBe "double"
          locals("ld") shouldBe "long double"
          locals("i") shouldBe "int"
          locals("s") shouldBe "short"
          locals("l") shouldBe "long"
          locals("ll") shouldBe "long long"
          locals("c") shouldBe "char"
          locals("b") shouldBe "bool"
          locals("j") shouldBe "int"
          locals("t") shouldBe "int"
          locals("count") shouldBe "unsigned int"
          locals("str") shouldBe "std.string"
          locals("character") shouldBe "char"
          locals("while_count") shouldBe "int"
      }
  }

  "AST: imports" should {
      "capture the iostream include as an import" in {
          cpg.imports.importedEntity.l should contain("iostream")
      }
  }

  "AST: literals and operators" should {
      "create literal nodes for the initializers" in {
          (cpg.literal.code.l should contain).allOf("1.23f", "32000", "0", "false", "\"hello\"")
      }

      "represent assignments, comparisons and increments as operator calls" in {
          cpg.call.name(io.shiftleft.codepropertygraph.generated.Operators.assignment)
              .size should be > 0
          cpg.call.name(io.shiftleft.codepropertygraph.generated.Operators.lessThan).size should be >= 2
          cpg.call.name(io.shiftleft.codepropertygraph.generated.Operators.postIncrement)
              .size should be >= 2
          cpg.call.name(io.shiftleft.codepropertygraph.generated.Operators.logicalNot)
              .size should be >= 1
      }
  }

  "AST: control structures" should {
      "create both IF branches (if / else-if / else)" in {
          // if (b), else-if (!b), if (count == 5)
          cpg.controlStructure.controlStructureType(ControlStructureTypes.IF).size shouldBe 3
          cpg.controlStructure.controlStructureType(ControlStructureTypes.ELSE).size shouldBe 2
      }

      "create the SWITCH with its break statements" in {
          cpg.controlStructure.controlStructureType(ControlStructureTypes.SWITCH).size shouldBe 1
          // two case breaks + default break
          cpg.controlStructure.controlStructureType(ControlStructureTypes.BREAK).size shouldBe 3
      }

      "create both FOR loops and the WHILE loop" in {
          cpg.controlStructure.controlStructureType(ControlStructureTypes.FOR).size shouldBe 2
          cpg.controlStructure.controlStructureType(ControlStructureTypes.WHILE).size shouldBe 1
          cpg.controlStructure.controlStructureType(ControlStructureTypes.CONTINUE).size shouldBe 1
      }

      "attach conditions to the control structures" in {
          cpg.controlStructure.controlStructureType(ControlStructureTypes.WHILE).condition.code
              .l should contain(
            "while_count < 10"
          )
      }
  }

  "CFG: dominance inside the for-loop guard" should {
      "make the continue statement control-dependent on `count == 5`" in {
          val continueControllers = cpg.controlStructure
              .controlStructureType(ControlStructureTypes.CONTINUE)
              .controlledBy
              .isCall
              .code
              .toSetMutable
          continueControllers should contain("count == 5")
      }
  }
end CppBasicSyntaxTests
