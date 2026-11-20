package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Local}
import io.shiftleft.semanticcpg.language.*

/** Which variable a GCC `cleanup` call releases, and where no call belongs: the argument binds to
  * the declared variable even where an inner scope declares the same name or the scope has ended, a
  * `static` local gets no call (GCC ignores the attribute on static storage), a jump inside the
  * variable's own initializer runs no cleanup for it, and a labelled final `return` is the last
  * statement control reaches.
  */
class CleanupAttributeScopeTests extends CCodeToCpgSuite:

  private lazy val cpg = code(
    """
      |#include <stdlib.h>
      |#include <string.h>
      |static void freep(void *pp) { free(*(void **)pp); }
      |#define _cleanup_free_ __attribute__((cleanup(freep)))
      |
      |int shadowed(int x) {
      |    _cleanup_free_ char *p = malloc(4);
      |    {
      |        char *p = 0;
      |        if (x) return 1;
      |    }
      |    return 0;
      |}
      |
      |int for_init(int n) {
      |    char *p = 0;
      |    for (_cleanup_free_ char *p = malloc(2); n > 0; n--) {}
      |    return p != 0;
      |}
      |
      |int static_local(void) {
      |    static char *g __attribute__((cleanup(freep)));
      |    return 0;
      |}
      |
      |int init_return(const char *s) {
      |    _cleanup_free_ char *q = ({ if (!s) return -1; strdup(s); });
      |    return q[0];
      |}
      |
      |int labelled_return(int n) {
      |    _cleanup_free_ char *c = malloc(8);
      |    if (n) goto out;
      |    n = 2;
      |out:
      |    return n;
      |}
      |""".stripMargin,
    "scope.c"
  )

  private def cleanupsIn(method: String): List[Call] =
      cpg.method.nameExact(method).ast.isCall.l
          .filter(_.tag.nameExact(X2CpgDefines.LifetimeEndTag).l.nonEmpty)

  /** The line of the local each cleanup call's argument refers to. */
  private def releasedLocalLines(method: String): List[Int] =
      cleanupsIn(method).flatMap(_.argument.isCall.argument.isIdentifier.l)
          .flatMap(_._refOut.collectAll[Local].l)
          .flatMap(_.lineNumber.map(Integer2int))

  "a cleanup call in a scope that shadows the variable" should {
      "release the variable the attribute is on, not the inner one" in {
          releasedLocalLines("shadowed") shouldBe List(8, 8)
      }
  }

  "the cleanup call that ends a for statement's declaration" should {
      "release the for statement's own variable" in {
          releasedLocalLines("for_init") shouldBe List(18)
      }
  }

  "a static local with the cleanup attribute" should {
      "get no cleanup call" in {
          cleanupsIn("static_local") shouldBe empty
      }
  }

  "a return inside the cleanup variable's own initializer" should {
      "run no cleanup for the variable it never initialised" in {
          // the only call is the one before the final return
          cleanupsIn("init_return").flatMap(_.lineNumber.map(Integer2int)) shouldBe List(29)
      }
  }

  "a labelled return that ends the function" should {
      "be the only exit that cleans up" in {
          cleanupsIn("labelled_return").flatMap(_.lineNumber.map(Integer2int)) shouldBe List(37)
      }
  }
end CleanupAttributeScopeTests
