package io.appthreat.c2cpg.passes.ast

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.shiftleft.codepropertygraph.generated.nodes.{Call, StoredNode}
import io.shiftleft.semanticcpg.language.*

/** Macro invocations as CDT's expansion records them: each with an index, nested ones under their
  * parent, the arguments found by where their tokens came from, and the nodes a definition wrote
  * pointing back at it.
  */
class MacroInvocationTests extends CCodeToCpgSuite:

  private def tagValues(n: StoredNode, name: String): List[String] =
      n.tag.nameExact(name).value.l

  "macro invocations" should {
      val cpg = code(
        """
          |#include "macros.h"
          |int nested(int a, int b, int c) { return MIN(a, MAX(b, c)); }
          |int constant_arg(int x) { return MIN(LIMIT, x); }
          |int repeated(int count) { return TWICE(count + 1); }
          |const char *named(void) { return NAME_OF(value); }
          |int pasted(int field_a) { return FIELD(a); }
          |int logged(int code) { return LOG("code %d", code); }
          |""".stripMargin,
        "use.c"
      ).moreCode(
        """
          |#define MIN(x, y) ((x) < (y) ? (x) : (y))
          |#define MAX(x, y) ((x) > (y) ? (x) : (y))
          |#define LIMIT 16
          |#define TWICE(v) ((v) + (v))
          |#define NAME_OF(s) #s
          |#define FIELD(n) field_##n
          |int log_message(const char *fmt, ...);
          |#define LOG(fmt, ...) log_message(fmt, __VA_ARGS__)
          |""".stripMargin,
        "macros.h"
      )

      def inlined(name: String): List[Call] =
          cpg.call.nameExact(name).dispatchTypeExact(DispatchTypes.INLINED).l

      "give each invocation its index, and a nested one its own under its parent's" in {
          val List(min) = inlined("MIN").filter(_.method.name == "nested")
          val minIndex  = tagValues(min, Defines.MacroInvocationTag)
          minIndex should have size 1
          // MAX(b, c) is written in MIN's argument: the frontend keeps the outermost invocation as
          // the call, and the nested one's expansion records it
          inlined("MAX") shouldBe empty
          val maxExpansion = min.astChildren.isBlock.ast.isCall.nameExact("<operator>.conditional")
              .filter(_.code == "(b) > (c) ? (b) : (c)").l
          maxExpansion should not be empty
          maxExpansion.foreach { c =>
            tagValues(c, Defines.MacroParentTag) shouldBe minIndex
            tagValues(c, Defines.MacroInvocationTag) should not be minIndex
          }
          inlined("TWICE").flatMap(tagValues(_, Defines.MacroInvocationTag)) should not be minIndex
      }

      "find each argument and copy it once, marked as a copy" in {
          val List(min) = inlined("MIN").filter(_.method.name == "nested")
          // the arguments are subtrees of the expansion: MAX(b, c) is its expansion
          min.argument.filterNot(_.isBlock).code.l shouldBe List("a", "(b) > (c) ? (b) : (c)")
          min.argument.filterNot(_.isBlock).ast.l.foreach { n =>
              tagValues(n, Defines.MacroArgumentCopyTag) shouldBe List("true")
          }
          // the expansion is not a copy
          min.astChildren.isBlock.ast.isIdentifier.l.foreach { n =>
              tagValues(n, Defines.MacroArgumentCopyTag) shouldBe empty
          }
      }

      "find an argument written as an expression once, though the expansion repeats it" in {
          val List(twice) = inlined("TWICE")
          twice.argument.filterNot(_.isBlock).code.l shouldBe List("count + 1")
      }

      "find an argument that is an object-like macro, and a plain one" in {
          val List(min) = inlined("MIN").filter(_.method.name == "constant_arg")
          val args      = min.argument.filterNot(_.isBlock).l
          args.map(_.label) shouldBe List("LITERAL", "IDENTIFIER")
          args.last.code shouldBe "x"
      }

      "point a node its definition wrote back at the definition" in {
          val List(log) = inlined("LOG")
          val origins = log.astChildren.isBlock.ast.isCall.nameExact("log_message")
              .flatMap(tagValues(_, Defines.MacroOriginTag)).l
          origins should have size 1
          origins.head should startWith("macros.h:9:")
      }

      "keep stringised, pasted and variadic invocations" in {
          inlined("NAME_OF") should have size 1
          inlined("FIELD") should have size 1
          val List(log) = inlined("LOG")
          log.argument.filterNot(_.isBlock).code.l should contain("code")
      }

      "keep the full name the clamp semantics key on" in {
          // `<definition file>:<line>:<line end>:<NAME>:<argc>`, read by DefaultSemantics' regexes
          val List(min) = inlined("MIN").filter(_.method.name == "nested")
          (min.methodFullName should fullyMatch).regex(""".*macros\.h:2:2:MIN:2""")
          (min.methodFullName should fullyMatch).regex(".*:MIN:\\d+$")
      }
  }
end MacroInvocationTests
