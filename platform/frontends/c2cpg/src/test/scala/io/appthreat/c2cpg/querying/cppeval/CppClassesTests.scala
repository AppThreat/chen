package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.{ControlStructureTypes, ModifierTypes}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** Evaluates AST creation for classes and structs: member declarations, constructors, methods,
  * return types, and the call graph (callers / callees) linking methods together.
  */
class CppClassesTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private implicit val resolver: NoResolve.type = NoResolve

  private val cpg = code("""
      |#include <iostream>
      |#include <random>
      |#include <string>
      |
      |struct player {
      |    std::string name;
      |    int total_money{ 0 };
      |};
      |
      |class number_generator {
      |public:
      |    number_generator(const int &min, const int &max)
      |        : random_engine_(random_device_()), uniform_int_distribution_(min, max) {}
      |    int generate_random_number() {
      |        return uniform_int_distribution_(random_engine_);
      |    }
      |private:
      |    std::random_device random_device_;
      |    std::default_random_engine random_engine_;
      |    std::uniform_int_distribution<int> uniform_int_distribution_;
      |};
      |
      |class game {
      |    player player_;
      |    number_generator number_generator_;
      |public:
      |    game(const player& player) : number_generator_(1, 10) {
      |        player_ = player;
      |    }
      |    int play_round() {
      |        const auto number = number_generator_.generate_random_number();
      |        player_.total_money += number;
      |        return number;
      |    }
      |    bool game_over() {
      |        return player_.total_money <= 0;
      |    }
      |};
      |
      |int main() {
      |    const player m_player;
      |    game g(m_player);
      |    do {
      |        const auto number = g.play_round();
      |        if (g.game_over()) {
      |            break;
      |        }
      |    } while (!g.game_over());
      |    return 0;
      |}
      |""".stripMargin)

  "AST: type declarations" should {
      "create TypeDecl nodes for the struct and both classes" in {
          val internal = cpg.typeDecl.internal.name.toSetMutable
          internal should contain allOf ("player", "number_generator", "game")
      }

      "capture the members of `player` with their types" in {
          val members = cpg.typeDecl.nameExact("player").member.map(m => m.name -> m.typeFullName).toMap
          members("name") shouldBe "std.string"
          members("total_money") shouldBe "int"
      }

      "capture the members of `game`" in {
          val members = cpg.typeDecl.nameExact("game").member.map(m => m.name -> m.typeFullName).toMap
          members("player_") shouldBe "player"
          members("number_generator_") shouldBe "number_generator"
      }

      "bind the methods to their owning type declarations" in {
          cpg.typeDecl.nameExact("game").method.name.toSetMutable should contain allOf (
            "game", "play_round", "game_over"
          )
          cpg.typeDecl.nameExact("number_generator").method.name.toSetMutable should contain allOf (
            "number_generator", "generate_random_number"
          )
      }
  }

  "AST: methods, return types and modifiers" should {
      "assign proper return types to the regular methods" in {
          cpg.method.nameExact("generate_random_number").methodReturn.typeFullName.head shouldBe "int"
          cpg.method.nameExact("play_round").methodReturn.typeFullName.head shouldBe "int"
          cpg.method.nameExact("game_over").methodReturn.typeFullName.head shouldBe "bool"
      }

      "not leak the method fullName into a constructor's return type (regression)" in {
          val ctor = cpg.method.nameExact("number_generator").head
          ctor.methodReturn.typeFullName shouldBe "ANY"
          ctor.signature should not include ctor.fullName
          ctor.signature shouldBe "ANY (int,int)"
      }

      "flag constructors with the CONSTRUCTOR modifier" in {
          cpg.method.nameExact("number_generator").isConstructor.l should not be empty
          cpg.method.nameExact("game").isConstructor.l should not be empty
          cpg.method.nameExact("generate_random_number").isConstructor.l shouldBe empty
      }

      "record constructor parameters" in {
          cpg.method.nameExact("game").parameter.nameExact("player").typeFullName.head shouldBe "player"
      }
  }

  "Call graph: callers and callees" should {
      "resolve the call to generate_random_number back to its definition" in {
          val call = cpg.call.nameExact("generate_random_number").head
          call.methodFullName shouldBe "number_generator.generate_random_number:int()"
      }

      "link play_round as the caller of generate_random_number" in {
          cpg.method.nameExact("generate_random_number").caller.name.toSetMutable should contain("play_round")
      }

      "list generate_random_number among the callees of play_round" in {
          cpg.method.nameExact("play_round").callee.fullName.toSetMutable should contain(
            "number_generator.generate_random_number:int()"
          )
      }

      "link main to play_round and game_over via the call graph" in {
          cpg.method.nameExact("main").call.nameExact("play_round").l should not be empty
          cpg.method.nameExact("main").call.nameExact("game_over").size should be >= 2
      }
  }

  "AST/CFG: main control flow" should {
      "create the do-while loop and the break in main" in {
          cpg.method("main").controlStructure.controlStructureType(ControlStructureTypes.DO).size shouldBe 1
          cpg.method("main").controlStructure.controlStructureType(ControlStructureTypes.BREAK).size shouldBe 1
          cpg.method("main").controlStructure.controlStructureType(ControlStructureTypes.IF).size shouldBe 1
      }

      "make the break control-dependent on the game_over guard" in {
          cpg.method("main").controlStructure
              .controlStructureType(ControlStructureTypes.BREAK)
              .controlledBy
              .isCall
              .name
              .toSetMutable should contain("game_over")
      }
  }
end CppClassesTests
