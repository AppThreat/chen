package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    ValueOriginPass
}
import io.shiftleft.semanticcpg.language.*

/** MS-ESC-001: the address of a stack local leaving its frame. Every positive mirrors a classic
  * shape (the CWE-562 stack-address return, a C++ reference return to a local); every negative
  * returns or stores storage that survives the frame.
  */
class StackEscapeRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |/* the three CWE-562 shapes */
    |char *bad_return_local(void)
    |{
    |    char buf[32];
    |    strcpy(buf, "hello");
    |    return buf;
    |}
    |
    |int *bad_return_local_int(void)
    |{
    |    int x = 42;
    |    return &x;
    |}
    |
    |static char **g_escape;
    |
    |void bad_escape_via_global(void)
    |{
    |    char buf[32];
    |    g_escape = (char **)&buf;
    |}
    |
    |/* the address held in a local, then returned */
    |char *bad_return_via_local(void)
    |{
    |    char inner[16];
    |    char *p = inner;
    |    return p;
    |}
    |
    |struct box { char *buf; };
    |
    |void bad_escape_via_member(struct box *b)
    |{
    |    char buf[32];
    |    b->buf = buf;
    |}
    |
    |char *good_heap(void)
    |{
    |    char *p = (char *)malloc(32);
    |    if (p == NULL) return NULL;
    |    strcpy(p, "hello");
    |    return p;
    |}
    |
    |const char *good_static_storage(void)
    |{
    |    return "hello";
    |}
    |
    |void good_escape_param_copy(char *out, int n)
    |{
    |    char buf[32];
    |    out = buf;
    |    out[0] = (char)n;
    |}
    |
    |/* designated initializers store into the object they initialise, not into a global */
    |struct pair { char *first; int n; };
    |void consume(struct pair);
    |
    |void good_designated_local(void)
    |{
    |    char storage[8];
    |    struct pair p = { .first = storage, .n = 1 };
    |    consume(p);
    |}
    |
    |void good_compound_literal(void)
    |{
    |    char storage[8];
    |    consume((struct pair){ .first = storage });
    |}
    |
    |#define PAIR_OF(s) { .first = (s), .n = 0 }
    |#define PAIR_WRITER(n) char cells[n]; struct pair w = (struct pair){ .first = cells, .n = n }
    |
    |void good_compound_literal_declared(void)
    |{
    |    PAIR_WRITER(8);
    |    consume(w);
    |}
    |
    |void good_designated_macro(void)
    |{
    |    char storage[8];
    |    struct pair p = PAIR_OF(storage);
    |    consume(p);
    |}
    |""".stripMargin,
    "stack_escape.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  /** MS-ESC findings only - the unchecked-parameter fixtures draw MS-NULL-001's low tier, which has
    * its own suite.
    */
  private def stackEscapesIn(method: String): Set[Int] =
      cpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.Expression]
          .filter(_.tag.name("ms-finding").value.l.contains("MS-ESC-001"))
          .map(_.lineNumber.map(_.toInt).getOrElse(-1))
          .l
          .toSet

  "MS-ESC-001" should:

    "fire on a returned array local (decay)" in {
        stackEscapesIn("bad_return_local") should not be empty
    }

    "fire on a returned &local" in {
        stackEscapesIn("bad_return_local_int") should not be empty
    }

    "fire on a stack address stashed into a global" in {
        stackEscapesIn("bad_escape_via_global") should not be empty
    }

    "fire on a stack address held in a local and then returned" in {
        stackEscapesIn("bad_return_via_local") should not be empty
    }

    "fire on a stack address stored into a struct member" in {
        stackEscapesIn("bad_escape_via_member") should not be empty
    }

    "stay silent on a returned heap allocation" in {
        stackEscapesIn("good_heap") shouldBe empty
    }

    "stay silent on a string literal (static storage)" in {
        stackEscapesIn("good_static_storage") shouldBe empty
    }

    "stay silent when a parameter is merely rebound to a local" in {
        // `out = buf` rebinds this frame's copy of the parameter; the callee cannot see it
        stackEscapesIn("good_escape_param_copy") shouldBe empty
    }

    "stay silent on a stack address a designated initializer stores into a local" in {
        stackEscapesIn("good_designated_local") shouldBe empty
        stackEscapesIn("good_designated_macro") shouldBe empty
    }

    "stay silent on a stack address stored into a compound literal" in {
        stackEscapesIn("good_compound_literal") shouldBe empty
        stackEscapesIn("good_compound_literal_declared") shouldBe empty
    }
end StackEscapeRuleTests
