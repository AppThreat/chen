package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.ModifierTypes
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Method}
import io.shiftleft.semanticcpg.language.*

/** A `static` function is visible only in its own translation unit: the call and method-ref linkers
  * must not connect another file's reference to a same-named static (libavformat defines 706
  * function names in more than one file).
  */
class InternalLinkageTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
      |#include "h.h"
      |struct nut { void *st[4]; };
      |static void pick_dup(struct nut *nut, int idx) { (void)nut->st[idx]; }
      |void (*const table[])(struct nut *, int) = { pick_dup };
      |int a_uses_header(int x) { return hinl(x); }
      |static int only_here(int x) { return x; }
      |""".stripMargin,
    "a.c"
  ).moreCode(
    """
      |struct nut { void *st[4]; };
      |static void pick_dup(struct nut *nut, int idx) { (void)nut; (void)idx; }
      |void b_caller(struct nut *nut) { pick_dup(nut, 0); }
      |static void (*b_ref)(struct nut *, int) = pick_dup;
      |""".stripMargin,
    "b.c"
  ).moreCode(
    """
      |int ext_fn(int x) { return x + 1; }
      |""".stripMargin,
    "c.c"
  ).moreCode(
    """
      |int ext_fn(int x);
      |int d_caller(int y) { return ext_fn(y); }
      |int only_here(int x);
      |int d_calls_elsewhere(int y) { return only_here(y); }
      |int later(int x);
      |int d_calls_later(int y) { return later(y); }
      |""".stripMargin,
    "d.c"
  ).moreCode(
    """
      |static int later(int x);
      |int later(int x) { return x; }
      |int e_calls_later(int y) { return later(y); }
      |""".stripMargin,
    "e.c"
  ).moreCode(
    """
      |static inline int hinl(int x) { return x * 2; }
      |""".stripMargin,
    "h.h"
  )

  private def methodIn(name: String, file: String): Method =
      cpg.method.nameExact(name).filter(_.filename.endsWith(file)).filter(
        _.block.astChildren.nonEmpty
      ).head

  private def callerFiles(m: Method): Set[String] =
      m._callIn.collectAll[Call].method.filename.l.map(_.split('/').last).toSet

  "a static function" should:
    "carry the static modifier" in {
        methodIn("pick_dup", "a.c").modifier.modifierType.l should contain(ModifierTypes.STATIC)
        methodIn("ext_fn", "c.c").modifier.modifierType.l should not contain ModifierTypes.STATIC
    }
    "not receive a same-named static's callers from another file" in {
        callerFiles(methodIn("pick_dup", "a.c")) shouldBe empty
        callerFiles(methodIn("pick_dup", "b.c")) shouldBe Set("b.c")
    }
    "be the target of its own file's method refs only" in {
        val refs = cpg.methodRef.methodFullNameExact("pick_dup").l
        refs.map(r =>
            (r.method.filename.split('/').last, r.referencedMethod.filename.split('/').last)
        )
            .toSet shouldBe Set(("a.c", "a.c"), ("b.c", "b.c"))
    }
    "not be the callee of another file's call to an external function of that name" in {
        callerFiles(methodIn("only_here", "a.c")) shouldBe empty
    }

  "a definition after a static prototype" should:
    "keep the prototype's internal linkage" in {
        methodIn("later", "e.c").modifier.modifierType.l should contain(ModifierTypes.STATIC)
        callerFiles(methodIn("later", "e.c")) shouldBe Set("e.c")
    }

  "a function with external linkage" should:
    "still link across files, prototype or not" in {
        callerFiles(methodIn("ext_fn", "c.c")) shouldBe Set("d.c")
    }
    "link a static inline header helper to its includer's call" in {
        callerFiles(methodIn("hinl", "h.h")) shouldBe Set("a.c")
    }
end InternalLinkageTests
