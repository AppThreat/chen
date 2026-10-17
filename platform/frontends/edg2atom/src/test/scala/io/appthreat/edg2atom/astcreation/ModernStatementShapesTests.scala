package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** What the language's statement forms declare: a C++17 selection statement's initialiser (if, if
  * constexpr and switch) declares what its condition reads.
  */
class ModernStatementShapesTests extends EdgCodeToCpgSuite(".cpp"):

  "an if-with-initialiser" should {
      val cpg = code(
        """#include <cstdio>
          |#include <cstdlib>
          |int pick(const char *user) {
          |  int table[8] = {0};
          |  if (int idx = atoi(user); idx > 0) {
          |    return table[idx];
          |  }
          |  return 0;
          |}
          |""".stripMargin
      )

      "declare its local, with its declared type, before the test reads it" in {
          requireEdga()
          cpg.method.nameExact("pick").local.nameExact("idx").typeFullName.l should
              contain("int")
          cpg.method.nameExact("pick").call.nameExact("atoi").l should not be empty
      }

      "keep the index the declaration initialises reachable" in {
          requireEdga()
          val idxUses = cpg.method.nameExact("pick").ast.isIdentifier.nameExact("idx").l
          idxUses.size should be > 1
      }
  }

  "a switch-with-initialiser" should {
      val cpg = code(
        """#include <cstdio>
          |#include <cstdlib>
          |int choose(const char *user) {
          |  switch (int code = atoi(user); code) {
          |    case 0:
          |      return code;
          |    default:
          |      return -1;
          |  }
          |}
          |""".stripMargin
      )

      "declare its local ahead of the cases" in {
          requireEdga()
          cpg.method.nameExact("choose").local.nameExact("code").typeFullName.l should
              contain("int")
          cpg.method.nameExact("choose").call.nameExact("atoi").l should not be empty
      }
  }

  "an if constexpr with an initialiser" should {
      val cpg = code(
        """#include <cstdio>
          |#include <cstdlib>
          |template <typename T>
          |int graded(const char *user) {
          |  if constexpr (int idx = atoi(user); sizeof(T) > 1) {
          |    return idx;
          |  } else {
          |    return 0;
          |  }
          |}
          |int run(const char *user) { return graded<int>(user); }
          |""".stripMargin
      )

      "keep the initialiser of the branch the instance takes" in {
          requireEdga()
          val idxLocals = cpg.method.name("graded.*").local.nameExact("idx").l
          idxLocals should not be empty
          cpg.method.name("graded.*").call.nameExact("atoi").l should not be empty
      }
  }

end ModernStatementShapesTests
