package io.appthreat.c2cpg.passes

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The declared attributes of a function whose header is OUTSIDE the analysed input - FFmpeg's
  * `libavutil/mem.h` in a `libavformat/`-scoped run, reached through `--include-path`. The header's
  * declarations are included nodes of each translation unit, so no METHOD is built from them; the
  * attributes ride on the CALLs instead, and the declared signature beside them.
  */
class HeaderFunctionAttributeTests extends AnyWordSpec with Matchers:

  private val header =
      """#include <stddef.h>
        |#define AV_GCC_VERSION_AT_LEAST(x,y) (__GNUC__ > (x) || __GNUC__ == (x) && __GNUC_MINOR__ >= (y))
        |#if AV_GCC_VERSION_AT_LEAST(3,1)
        |    #define av_malloc_attrib __attribute__((__malloc__))
        |#else
        |    #define av_malloc_attrib
        |#endif
        |#if AV_GCC_VERSION_AT_LEAST(4,3)
        |    #define av_alloc_size(...) __attribute__((alloc_size(__VA_ARGS__)))
        |#else
        |    #define av_alloc_size(...)
        |#endif
        |av_malloc_attrib av_alloc_size(1) void *av_malloc(size_t size);
        |av_alloc_size(2, 3) void *av_realloc_array(void *ptr, size_t nmemb, size_t size);
        |char *av_strndup(const char *s, size_t len) av_malloc_attrib;
        |void av_free(void *ptr);
        |""".stripMargin

  private def withScopedRun[T](f: Cpg => T): T =
    val root = File.newTemporaryDirectory("hdrattr")
    try
      (root / "libavutil").createDirectories()
      (root / "libavformat").createDirectories()
      (root / "libavutil" / "mem.h").write(header)
      (root / "libavformat" / "a.c").write(
        """#include "libavutil/mem.h"
          |char *f(int n, void *q) {
          |  char *p = av_malloc(n);
          |  q = av_realloc_array(q, n, 4);
          |  av_free(q);
          |  return av_strndup(p, n);
          |}
          |char *g(int n) { return av_malloc(n); }
          |""".stripMargin
      )
      val out = File.newTemporaryFile("hdrattr", ".atom")
      out.deleteOnExit()
      val cpg = new C2Cpg().createCpg(
        Config()
            .withInputPath((root / "libavformat").pathAsString)
            .withOutputPath(out.pathAsString)
            .withIncludePaths(Set(root.pathAsString))
            .withAstCache(false)
            .withFunctionBodies(true)
      ).get
      try f(cpg)
      finally cpg.close()
    finally root.delete(swallowIOExceptions = true)
  end withScopedRun

  private def callAttrs(cpg: Cpg, name: String): Set[String] =
      cpg.call.nameExact(name).tag.nameExact(Defines.FunctionAttributeTag).value.toSet

  "a header outside the analysed input" should:
    "put its declared attributes on every call" in withScopedRun { cpg =>
        callAttrs(cpg, "av_malloc") shouldBe Set("malloc", "alloc_size(1)")
        cpg.call.nameExact("av_malloc").l.map(
          _.tag.nameExact(Defines.FunctionAttributeTag).value.toSet
        ) shouldBe List.fill(2)(Set("malloc", "alloc_size(1)"))
        callAttrs(cpg, "av_realloc_array") shouldBe Set("alloc_size(2,3)")
        callAttrs(cpg, "av_strndup") shouldBe Set("malloc")
    }
    "leave a call to an unattributed declaration untagged" in withScopedRun { cpg =>
        callAttrs(cpg, "av_free") shouldBe empty
    }
    "keep the declared pointer shape in the call's signature" in withScopedRun { cpg =>
        // size_t is ANY here: the test has no system include path
        cpg.call.nameExact("av_realloc_array").signature.l.distinct shouldBe List(
          "void*(void*,ANY,ANY)"
        )
    }
end HeaderFunctionAttributeTests

/** A function declared more than once in one file: the attributes of every declaration count, not
  * only those of the first one seen.
  */
class RedeclaredFunctionAttributeTests extends CCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stddef.h>
    |void *first_plain(size_t n);
    |void *first_plain(size_t n) __attribute__((malloc));
    |__attribute__((malloc, alloc_size(1))) void *def_after(size_t n);
    |void *def_after(size_t n) { return NULL; }
    |""".stripMargin,
    "redecl.c"
  )

  private def attrsOf(name: String): Set[String] =
      cpg.method.nameExact(name).tag.name(Defines.FunctionAttributeTag).value.l.toSet

  "a redeclared function" should:
    "keep the attributes of a later declaration" in {
        attrsOf("first_plain") shouldBe Set("malloc")
    }
    "carry a declaration's attributes onto its definition" in {
        attrsOf("def_after") shouldBe Set("malloc", "alloc_size(1)")
    }
end RedeclaredFunctionAttributeTests

/** A cached AST is only replayed for the frontend format and include configuration that built it. */
class AstCacheFingerprintTests extends AnyWordSpec with Matchers:
  "the AST cache fingerprint" should:
    "differ by include path and define, and be stable otherwise" in {
        val base = Config().withInputPath("/x")
        AstCreationPass.cacheFingerprint(base) should not be empty
        AstCreationPass.cacheFingerprint(base) shouldBe AstCreationPass.cacheFingerprint(base)
        AstCreationPass.cacheFingerprint(base.withIncludePaths(Set("/y"))) should not be
            AstCreationPass.cacheFingerprint(base)
        AstCreationPass.cacheFingerprint(base.withDefines(Set("A=1"))) should not be
            AstCreationPass.cacheFingerprint(base)
    }
