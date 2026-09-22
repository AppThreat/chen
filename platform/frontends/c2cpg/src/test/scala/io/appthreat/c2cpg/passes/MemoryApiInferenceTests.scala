package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.MemoryApiPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** The C2 wrapper inference: allocator and free-wrapper roles concluded from what method bodies do.
  * Every positive has its negative beside it - the shapes the inference must NOT conclude.
  */
class MemoryApiInferenceTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |void *my_alloc(int n) {
    |    void *p = malloc(n);
    |    if (!p) return NULL;
    |    return p;
    |}
    |
    |void *wrap_direct(size_t n) {
    |    return malloc(n);
    |}
    |
    |void *wrap_cast(size_t n) {
    |    return (char *)malloc(n * 4);
    |}
    |
    |void *wrap_of_wrap(int n) {
    |    return my_alloc(n);
    |}
    |
    |void my_free(void *p) {
    |    free(p);
    |}
    |
    |void *returns_param(void *p) {
    |    return p;
    |}
    |
    |void *alloc_then_free(int n) {
    |    void *p = malloc(n);
    |    free(p);
    |    return p;
    |}
    |
    |void *alloc_and_log(int n) {
    |    void *p = malloc(n);
    |    log_ptr(p);
    |    return p;
    |}
    |
    |void *only_literal_return(int n) {
    |    malloc(n);
    |    return 0;
    |}
    |
    |void use_wrappers(void) {
    |    char *a = my_alloc(64);
    |    char *b = wrap_direct(8);
    |    char *c = wrap_cast(8);
    |    char *d = wrap_of_wrap(16);
    |    char *e = returns_param(a);
    |    char *f = alloc_then_free(8);
    |    char *g = alloc_and_log(8);
    |    char *h = only_literal_return(2);
    |    memcpy(a, b, 4);
    |    memcpy(h, g, 4);
    |    memcpy(c, d, 4);
    |    memcpy(e, f, 4);
    |    memcpy(g, a, 4);
    |    my_free(a);
    |    my_free(b);
    |}
    |""".stripMargin,
    "wrappers.c"
  )

  new MemoryApiPass(cpg).createAndApply()

  "MemoryApiPass wrapper inference" should:

    "conclude an allocator from a NULL-guarded allocation flow" in {
        cpg.call.name("my_alloc").l should not be empty
        cpg.call.name("my_alloc").l.foreach { site =>
          site.tag.name("mem-alloc").value.l shouldBe List("heap")
          // the size role travels: the parameter feeding malloc's size argument
          site.argument(1).tag.name("mem-len").value.l shouldBe List("my_alloc")
        }
    }

    "conclude an allocator from a direct and a cast-wrapped return" in {
        cpg.call.name("wrap_direct").tag.name("mem-alloc").value.l shouldBe List("heap")
        cpg.call.name("wrap_cast").tag.name("mem-alloc").value.l shouldBe List("heap")
        // the size is `n * 4`, not the parameter alone; one parameter still feeds it
        cpg.call.name("wrap_cast").argument(1).tag.name("mem-len").value.l shouldBe List(
          "wrap_cast"
        )
    }

    "chain a wrapper of an inferred wrapper within the round bound" in {
        cpg.call.name("wrap_of_wrap").tag.name("mem-alloc").value.l shouldBe List("heap")
    }

    "conclude a free wrapper" in {
        cpg.call.name("my_free").l should not be empty
        cpg.call.name("my_free").l.foreach { site =>
            site.tag.name("mem-free").value.l shouldBe List("heap")
        }
    }

    "not conclude an allocator that returns its parameter" in {
        cpg.call.name("returns_param").l.foreach { site =>
            site.tag.name("mem-alloc").l shouldBe Nil
        }
    }

    "not conclude a wrapper whose body frees what it allocates" in {
        cpg.call.name("alloc_then_free").l.foreach { site =>
          site.tag.name("mem-alloc").l shouldBe Nil
          site.tag.name("mem-free").l shouldBe Nil
        }
    }

    "not conclude a wrapper with behaviour beyond the allocation" in {
        cpg.call.name("alloc_and_log").l.foreach { site =>
            site.tag.name("mem-alloc").l shouldBe Nil
        }
    }

    "emit inferred roles as ordinary tags at the call sites, umbrella included" in {
        val site = cpg.call.name("my_alloc").head
        site.tag.name.l should contain("memory-safety")
        // and the mem-len argument node carries it too, exactly like inventory roles
        site.argument(1).tag.name.l should contain("memory-safety")
    }
end MemoryApiInferenceTests

/** Inference against a declared inventory: an agreement changes nothing, and a disagreement is
  * reported with the declaration winning.
  */
class MemoryApiInferenceDisagreementTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <stdlib.h>
    |
    |void *declared_alloc(size_t n) {
    |    return malloc(n);
    |}
    |
    |void *name_says_free(size_t n) {
    |    return malloc(n);
    |}
    |
    |void use_both(void) {
    |    void *a = declared_alloc(4);
    |    void *b = name_says_free(4);
    |    free(a);
    |}
    |""".stripMargin,
    "declared.c"
  )

  new MemoryApiPass(
    cpg,
    Some(
      """{"version": 1, "apis": [
        |  {"name": "declared_alloc", "alloc": "heap"},
        |  {"name": "name_says_free", "free": "heap"}
        |]}""".stripMargin
    )
  ).createAndApply()

  "MemoryApiPass inference vs a declared inventory" should:

    "leave an agreed function tagged exactly once, by the declaration" in {
        val sites = cpg.call.name("declared_alloc").l
        sites should not be empty
        sites.foreach { site =>
            site.tag.name("mem-alloc").value.l shouldBe List("heap")
        }
    }

    "keep the declaration when inference concludes the opposite" in {
        val sites = cpg.call.name("name_says_free").l
        sites should not be empty
        // the body is a clean allocation flow, so inference concludes allocator; the declared
        // free role wins and no allocator tag may appear beside it
        sites.foreach { site =>
          site.tag.name("mem-free").value.l shouldBe List("heap")
          site.tag.name("mem-alloc").l shouldBe Nil
        }
    }
end MemoryApiInferenceDisagreementTests
