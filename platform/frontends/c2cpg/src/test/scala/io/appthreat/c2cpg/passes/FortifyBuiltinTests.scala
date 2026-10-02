package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.{Call, StoredNode}
import io.shiftleft.semanticcpg.language.*

/** The C library's `_FORTIFY_SOURCE` wrappers (`__memcpy_chk`), the compiler's spellings of them
  * (`__builtin___memcpy_chk`) and the compiler builtins of library functions (`__builtin_memcpy`)
  * are read as the functions they stand for: the same argument roles and findings, and the same
  * data flow. A wrapper's destination size is capacity evidence.
  */
class FortifyBuiltinTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |typedef unsigned long size_t;
    |char *getenv(const char *name);
    |int system(const char *cmd);
    |
    |void plain(const char *src, unsigned n) {
    |    char buf[16];
    |    memcpy(buf, src, n);
    |}
    |
    |void fortified(const char *src, unsigned n) {
    |    char buf[16];
    |    __builtin___memcpy_chk(buf, src, n, __builtin_object_size(buf, 0));
    |}
    |
    |void glibc_wrapper(const char *src, unsigned n) {
    |    char buf[16];
    |    __memcpy_chk(buf, src, n, 16);
    |}
    |
    |void builtin(const char *src, unsigned n) {
    |    char buf[16];
    |    __builtin_memcpy(buf, src, n);
    |}
    |
    |void known_size_only(char *dst, const char *src, unsigned n) {
    |    __builtin___memcpy_chk(dst, src, n, 32);
    |}
    |
    |void unknown_size(char *dst, const char *src, unsigned n) {
    |    __builtin___memcpy_chk(dst, src, n, (size_t)-1);
    |}
    |
    |void formatted(const char *name) {
    |    char cmd[64];
    |    __builtin___sprintf_chk(cmd, 0, sizeof(cmd), "%s", getenv(name));
    |    system(cmd);
    |}
    |
    |void copied(const char *name) {
    |    char cmd[64];
    |    __builtin___strcpy_chk(cmd, getenv(name), sizeof(cmd));
    |    system(cmd);
    |}
    |
    |void sink(const char *p);
    |void length_plain(const char *src, unsigned n) { char b[16]; memcpy(b, src, n); sink(b); }
    |void length_fortified(const char *src, unsigned n) {
    |    char b[16];
    |    __builtin___memcpy_chk(b, src, n, 16);
    |    sink(b);
    |}
    |void length_opaque(const char *src, unsigned n) { char b[16]; opaque(b, src, n, 16); sink(b); }
    |
    |unsigned long length(const char *s) { return __builtin_strlen(s); }
    |""".stripMargin,
    "fortify.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def copyIn(method: String): Call =
      cpg.method.nameExact(method).call.filter(_.argument.size >= 3).head

  private def rolesOf(call: Call): List[(Int, String, String)] =
      call.argument.l.flatMap { a =>
          a.tag.l.filter(t => t.name.startsWith("mem-")).map(t =>
              (a.argumentIndex, t.name, t.value)
          )
      }.sorted

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l).toSet

  private def extentOfDestination(method: String): List[String] =
      copyIn(method).argument(1).tag.name(ExtentPass.TagExtent).value.l

  "a FORTIFY wrapper or builtin of memcpy" should {
      "carry memcpy's argument roles, valued memcpy" in {
          val expected =
              List((1, "mem-dst", "memcpy"), (2, "mem-src", "memcpy"), (3, "mem-len", "memcpy"))
          rolesOf(copyIn("plain")) shouldBe expected
          rolesOf(copyIn("fortified")) shouldBe expected :+ ((4, "mem-object-size", "memcpy"))
          rolesOf(copyIn("glibc_wrapper")) shouldBe expected :+ ((4, "mem-object-size", "memcpy"))
          rolesOf(copyIn("builtin")) shouldBe expected
      }

      "give the same findings as the plain call" in {
          val plain = findingsIn("plain")
          plain should not be empty
          findingsIn("fortified") shouldBe plain
          findingsIn("glibc_wrapper") shouldBe plain
          findingsIn("builtin") shouldBe plain
      }

      "keep the destination's extent" in {
          extentOfDestination("plain") shouldBe List("const:16")
          extentOfDestination("fortified") shouldBe List("const:16")
          extentOfDestination("glibc_wrapper") shouldBe List("const:16")
      }
  }

  "a FORTIFY wrapper's destination size" should {
      "be the capacity of a destination nothing else sizes" in {
          extentOfDestination("known_size_only") shouldBe List("const:32")
      }

      "say nothing when the compiler did not know it" in {
          extentOfDestination("unknown_size") shouldBe List("unknown")
      }
  }

  "data flow" should {
      "pass through the wrappers as through the functions they stand for" in {
          def sinkIn(method: String) =
              cpg.method.nameExact(method).call.nameExact("system").argument
          def sources = cpg.call.nameExact("getenv")
          sinkIn("formatted").reachableBy(sources).l should not be empty
          sinkIn("copied").reachableBy(sources).l should not be empty
      }

      "not carry the length or the destination size into the destination" in {
          def lengthReaches(method: String) =
              cpg.method.nameExact(method).call.nameExact("sink").argument
                  .reachableBy(cpg.method.nameExact(method).parameter.nameExact("n")).l
          lengthReaches("length_plain") shouldBe empty
          lengthReaches("length_fortified") shouldBe empty
          // the control: a call without a summary is taken to fill every argument from every other
          lengthReaches("length_opaque") should not be empty
      }
  }

  "a builtin of strlen" should {
      "read its argument as strlen does" in {
          cpg.call.nameExact("__builtin_strlen").argument(1).tag.name("mem-src").value.l shouldBe
              List("strlen")
      }
  }
end FortifyBuiltinTests
