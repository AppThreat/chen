package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.{CCodeToCpgSuite, DataFlowCodeToCpgSuite}
import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** Entities across translation units, as C's linkage rules connect them. */
class CrossFileLinkageTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
      |#include <string.h>
      |#include "ctx_a.h"
      |#include "api.h"
      |static int counter;
      |int shared_total;
      |static void *helper(void) __attribute__((malloc));
      |void bump_a(void) { counter++; shared_total++; }
      |int read_a(struct ctx *c) { return c->len + api(1); }
      |void copy_a(struct ctx *c, const char *s) { memcpy(c->buf, s, 20); }
      |""".stripMargin,
    "a.c"
  ).moreCode(
    """
      |#include <string.h>
      |#include "ctx_b.h"
      |#include "api.h"
      |static int counter;
      |extern int shared_total;
      |void *helper(void) { return 0; }
      |void bump_b(void) { counter += 2; shared_total += 2; }
      |int read_b(struct ctx *c) { return c->len + api(2); }
      |void copy_b(struct ctx *c, const char *s) { memcpy(c->buf, s, 20); }
      |""".stripMargin,
    "b.c"
  ).moreCode(
    """
      |#include <stdlib.h>
      |#include "api.h"
      |int api(int n) { return n * 2; }
      |void *make(int n) { return malloc(n); }
      |""".stripMargin,
    "api.c"
  ).moreCode("int api(int n);\nvoid *make(int n) __attribute__((malloc));\n", "api.h")
      .moreCode("struct ctx { char buf[16]; int len; };\n", "ctx_a.h")
      .moreCode("struct ctx { int len; char *buf; };\n", "ctx_b.h")

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l).l.toSet

  "a function declared in a header and defined in another file" should {
      "be one callee: the definition" in {
          cpg.call.nameExact("api").l.map(_._callOut.collectAll[Method].map(_.filename).l) shouldBe
              List(List("api.c"), List("api.c"))
      }
      "carry the attributes its prototype declares" in {
          cpg.method.nameExact("make").filter(_.filename == "api.c")
              .tag.nameExact(Defines.FunctionAttributeTag).value.l should contain("malloc")
      }
      "not take the attributes of another file's static prototype" in {
          cpg.method.nameExact("helper").filter(_.filename == "b.c")
              .tag.nameExact(Defines.FunctionAttributeTag).value.l should not contain "malloc"
      }
  }

  "a file-scope variable" should {
      "be its own file's when static" in {
          cpg.local.nameExact("counter").l.map(l =>
              (l.method.filename.head, l.referencingIdentifiers.method.name.l.distinct)
          ).sortBy(_._1) shouldBe List(("a.c", List("bump_a")), ("b.c", List("bump_b")))
      }
  }

  "a struct two headers define differently" should {
      "be the layout of the header the file includes" in {
          // ctx_a.h: buf is char[16], so copying 20 bytes overruns it
          findingsIn("copy_a") should contain("MS-BOUND-006")
          // ctx_b.h: buf is a pointer of unknown capacity
          findingsIn("copy_b") should not contain "MS-BOUND-006"
      }
  }
end CrossFileLinkageTests

/** C++ entities in an anonymous namespace have internal linkage, like a `static` function. */
class AnonymousNamespaceLinkageTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  "a function in an anonymous namespace" should {
      val cpg = code(
        """
          |namespace { int helper() { return 1; } }
          |int run_a() { return helper(); }
          |""".stripMargin,
        "a.cpp"
      ).moreCode(
        """
          |namespace { int helper() { return 2; } }
          |int run_b() { return helper(); }
          |""".stripMargin,
        "b.cpp"
      )

      "be reached only from its own file" in {
          cpg.call.nameExact("helper").l.map(c =>
              (c.method.filename, c._callOut.collectAll[Method].map(_.filename).l)
          ).sortBy(_._1) shouldBe List(("a.cpp", List("a.cpp")), ("b.cpp", List("b.cpp")))
      }
  }
end AnonymousNamespaceLinkageTests

/** A struct that two headers outside the project define differently: each file sees the layout of
  * the header it includes.
  */
class OutsideHeaderLayoutTests extends DataFlowCodeToCpgSuite:

  private val outside = java.nio.file.Files.createTempDirectory("outside-headers")
  java.nio.file.Files.writeString(
    outside.resolve("ctx_a.h"),
    "struct ctx { char buf[16]; int len; };\n"
  )
  java.nio.file.Files.writeString(
    outside.resolve("ctx_b.h"),
    "struct ctx { int len; char *buf; };\n"
  )
  outside.toFile.deleteOnExit()

  private val cpg = code(
    """
      |#include <string.h>
      |#include <ctx_a.h>
      |void copy_a(struct ctx *c, const char *s) { memcpy(c->buf, s, 20); }
      |""".stripMargin,
    "a.c"
  ).moreCode(
    """
      |#include <string.h>
      |#include <ctx_b.h>
      |void copy_b(struct ctx *c, const char *s) { memcpy(c->buf, s, 20); }
      |""".stripMargin,
    "b.c"
  ).withConfig(io.appthreat.c2cpg.Config().withIncludePaths(Set(outside.toString)))

  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l).l.toSet

  "a header struct with two layouts" should {
      "keep both, one per header" in {
          cpg.typeDecl.nameExact("ctx").map(_.member.name.l).l.sortBy(_.head) shouldBe
              List(List("buf", "len"), List("len", "buf"))
      }
      "give each file the layout its include brings in" in {
          findingsIn("copy_a") should contain("MS-BOUND-006")
          findingsIn("copy_b") should not contain "MS-BOUND-006"
      }
  }
end OutsideHeaderLayoutTests
