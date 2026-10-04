package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.ModifierTypes
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Literal}
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

  "a global initialised at compile time" should {
      val cpg = code(
        """static const int limit = 64;
        |int table_size = 4 * 16;
        |const char *greeting = "hi";
        |int use(void) { return limit + table_size + greeting[0]; }
        |""".stripMargin
      )

      "be assigned its value at the declaration" in {
          requireEdga()
          cpg.method.nameExact("<global>").assignment.code.l.sorted shouldBe List(
            "greeting = \"hi\"",
            "limit = 64",
            "table_size = 4 * 16"
          )
          inside(cpg.assignment.code("limit = .*").argument(2).l) { case List(value: Literal) =>
              value.code shouldBe "64"
          }
          // the folded value is kept on the expression as written
          cpg.assignment.code("table_size = .*").argument(2).tag
              .nameExact(X2CpgDefines.ConstValueTag).value.l shouldBe List("64")
      }
  }

  "an enumerator" should {
      val cpg = code(
        """enum mode { MODE_READ = 1, MODE_WRITE, MODE_BOTH = MODE_READ | MODE_WRITE };
        |static const char *const names[4] = {"none", "read", "write", "both"};
        |int open_as(int how);
        |int open_both(void) { return open_as(MODE_BOTH); }
        |const char *name_of(enum mode m) { return names[m]; }
        |""".stripMargin
      )

      "be named where it is used, with its value" in {
          requireEdga()
          inside(cpg.call.nameExact("open_as").argument(1).l) { case List(arg: Identifier) =>
              arg.name shouldBe "MODE_BOTH"
              arg.tag.nameExact(X2CpgDefines.ConstValueTag).value.l shouldBe List("3")
          }
      }

      "be a member of its enumeration's TYPE_DECL, declared as written" in {
          requireEdga()
          val mode = cpg.typeDecl.nameExact("mode").head
          mode.code should startWith("enum mode {")
          mode.member.code.l shouldBe List(
            "MODE_READ = 1",
            "MODE_WRITE",
            "MODE_BOTH = MODE_READ | MODE_WRITE"
          )
      }
  }

  "an implicit arithmetic conversion" should {
      val cpg = code(
        """unsigned short add(unsigned short a, unsigned short b) {
        |  unsigned short s = a + b;
        |  return s;
        |}
        |long widen(int i) { long l = i; return l; }
        |unsigned flip(int i) { unsigned u = i; return u; }
        |int truncate(double d) { int k = d; return k; }
        |""".stripMargin
      )

      def conversionsIn(method: String) =
          cpg.method.nameExact(method).ast.collectAll[
            io.shiftleft.codepropertygraph.generated.nodes.Expression
          ]
              .flatMap(e =>
                  e.tag.nameExact(X2CpgDefines.ImplicitConversionTag).value.l.map(e.code -> _)
              )
              .l.sorted

      "be on the value converted, with its kind" in {
          requireEdga()
          conversionsIn("add") shouldBe List(
            "a"     -> "unsigned short->int:promotion",
            "a + b" -> "int->unsigned short:narrowing",
            "b"     -> "unsigned short->int:promotion"
          )
          conversionsIn("widen") shouldBe List("i" -> "int->long:arithmetic")
          conversionsIn("flip") shouldBe List("i" -> "int->unsigned int:sign-change")
          conversionsIn("truncate") shouldBe List("d" -> "double->int:narrowing")
      }
  }
end CShapesTests
