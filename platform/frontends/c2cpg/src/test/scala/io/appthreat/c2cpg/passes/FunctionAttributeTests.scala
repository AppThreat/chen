package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines
import io.shiftleft.semanticcpg.language.*

/** GCC function attributes reach the METHOD as `fn-attr` tags - the declared memory semantics of a
  * function whose body is out of scope.
  */
class FunctionAttributeTests extends CCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stddef.h>
    |#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
    |#define my_malloc_attrib __attribute__((__malloc__))
    |#define my_alloc_size(...) __attribute__((alloc_size(__VA_ARGS__)))
    |#else
    |#define my_malloc_attrib
    |#define my_alloc_size(...)
    |#endif
    |
    |void *my_malloc(size_t size) my_malloc_attrib my_alloc_size(1);
    |void *my_calloc(size_t nmemb, size_t size) my_malloc_attrib my_alloc_size(1, 2);
    |__attribute__((returns_nonnull)) char *my_name(void);
    |void my_copy(char *dst, const char *src) __attribute__((nonnull(1, 2)));
    |int plain(int x);
    |
    |__attribute__((malloc)) void *defined_alloc(size_t n) { return 0; }
    |""".stripMargin,
    "attrs.c"
  )

  private def attrsOf(name: String): Set[String] =
      cpg.method.nameExact(name).tag.name(Defines.FunctionAttributeTag).value.l.toSet

  "function attributes" should:
    "reach a declaration through the macros that gate them on __GNUC__" in {
        attrsOf("my_malloc") shouldBe Set("malloc", "alloc_size(1)")
        attrsOf("my_calloc") shouldBe Set("malloc", "alloc_size(1,2)")
    }
    "reach leading and trailing attribute forms" in {
        attrsOf("my_name") shouldBe Set("returns_nonnull")
        attrsOf("my_copy") shouldBe Set("nonnull(1,2)")
    }
    "reach a definition" in { attrsOf("defined_alloc") shouldBe Set("malloc") }
    "leave an unattributed function untagged" in { attrsOf("plain") shouldBe empty }
end FunctionAttributeTests
