package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.ModifierTypes
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

/** What C declares beyond the code: function attributes, `cleanup`, and the calls that return twice
  * or never.
  */
class CShapesTests extends EdgCodeToCpgSuite(".c"):

  private def attributesOf(node: io.shiftleft.codepropertygraph.generated.nodes.StoredNode) =
      node.tag.nameExact(X2CpgDefines.FunctionAttributeTag).value.l

  "a function's attributes" should {
      val cpg = code(
        """#include <stddef.h>
        |#include <setjmp.h>
        |void *my_alloc(size_t n) __attribute__((malloc, alloc_size(1), warn_unused_result));
        |int my_log(const char *fmt, ...) __attribute__((format(printf, 1, 2), nonnull(1)));
        |void my_fill(char *buf, size_t n) __attribute__((access(write_only, 1, 2)));
        |static void unlock(int *p) { *p = 0; }
        |static jmp_buf env;
        |int scoped(void) {
        |  int guard __attribute__((cleanup(unlock))) = 1;
        |  if (setjmp(env)) return 1;
        |  char *b = my_alloc(16);
        |  my_fill(b, 16);
        |  my_log("%s\n", b);
        |  longjmp(env, 2);
        |  return guard;
        |}
        |""".stripMargin
      )

      "be on its METHOD as the CDT frontend renders them" in {
          requireEdga()
          (attributesOf(cpg.method.nameExact("my_alloc").head) should contain).allOf(
            "malloc",
            "alloc_size(1)",
            "warn_unused_result"
          )
          (attributesOf(cpg.method.nameExact("my_log").head) should contain).allOf(
            "format(printf,1,2)",
            "nonnull(1)"
          )
          attributesOf(cpg.method.nameExact("my_fill").head) should contain(
            "access(write_only,1,2)"
          )
          cpg.method.nameExact("unlock").head.modifier.modifierType.l should contain(
            ModifierTypes.STATIC
          )
      }

      "be on its calls, with the header a library function is declared in" in {
          requireEdga()
          val longjmp = cpg.call.nameExact("longjmp").head
          attributesOf(longjmp) should contain("noreturn")
          longjmp.tag.nameExact("callee-declared-in").value.l.head should endWith("setjmp.h")
          attributesOf(cpg.call.nameExact("my_alloc").head) should contain("alloc_size(1)")
      }

      "mark the calls that return twice" in {
          requireEdga()
          val setjmps = cpg.call.name("_?setjmp").l
          setjmps should not be empty
          setjmps.flatMap(attributesOf) should contain("returns_twice")
      }

      "call a cleanup function with the variable's address where its scope ends" in {
          requireEdga()
          // the early return and the last one each leave the scope
          val cleanups = cpg.method.nameExact("scoped").call.nameExact("unlock").l
          cleanups.map(_.code) shouldBe List("unlock(&guard)", "unlock(&guard)")
          inside(cleanups.head.argument(1)) { case address: Call =>
              address.name shouldBe "<operator>.addressOf"
              address.argument(1).code shouldBe "guard"
          }
      }
  }
end CShapesTests
