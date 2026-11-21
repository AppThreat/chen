package io.appthreat.c2cpg.parser

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Paths

/** The text check that decides whether a header's owner is worth a second parse: it may say yes
  * where the parse then says no, but never no where the parse would say yes.
  */
class HeaderFromOwnerPrecheckTests extends AnyWordSpec with Matchers:

  private val header = Paths.get("/project/src/impl.h")

  private def mayProvide(owner: String, guarded: Boolean, unresolved: Set[String]): Boolean =
      HeaderFromOwner.ownerMayProvide(owner.toCharArray, header, guarded, unresolved)

  "the owner check" should {

      "pass a typedef the owner declares before including the header" in {
          val owner =
              """typedef struct { int n; } ctx_t;
                |#include "impl.h"
                |int main(void) { return 0; }
                |""".stripMargin
          mayProvide(owner, guarded = true, Set("ctx_t")) shouldBe true
      }

      "reject names the owner spells only after the include" in {
          val owner =
              """#include "impl.h"
                |typedef struct { int n; } ctx_t;
                |""".stripMargin
          mayProvide(owner, guarded = true, Set("ctx_t")) shouldBe false
      }

      "reject names the owner reaches only through an earlier include" in {
          val owner =
              """#include <config.h>
                |#include "impl.h"
                |""".stripMargin
          mayProvide(owner, guarded = true, Set("ngx_uint_t")) shouldBe false
      }

      "ignore names and braces inside comments and string literals" in {
          val owner =
              """/* ctx_t is declared in impl.h { */
                |const char *s = "ctx_t {";
                |#include "impl.h"
                |""".stripMargin
          mayProvide(owner, guarded = false, Set("ctx_t")) shouldBe false
      }

      "pass an unguarded header included inside braces" in {
          val owner =
              """enum op {
                |#include "impl.h"
                |};
                |""".stripMargin
          mayProvide(owner, guarded = false, Set.empty) shouldBe true
      }

      "reject a guarded header included inside braces with nothing unresolved" in {
          val owner =
              """enum op {
                |#include "impl.h"
                |};
                |""".stripMargin
          mayProvide(owner, guarded = true, Set.empty) shouldBe false
      }

      "match the include by the header's file name through a directory" in {
          val owner =
              """typedef int ctx_t;
                |#include "src/impl.h"
                |""".stripMargin
          mayProvide(owner, guarded = true, Set("ctx_t")) shouldBe true
      }

      "reject an owner that never includes a file of the header's name" in {
          mayProvide(
            "typedef int ctx_t;\n#include \"other.h\"\n",
            guarded = false,
            Set("ctx_t")
          ) shouldBe
              false
      }
  }
end HeaderFromOwnerPrecheckTests
