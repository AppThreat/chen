package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 10, tasks 4 and 5: the uncontrolled-allocation tiers and the strlen stand-down, the
  * lossy-cast fold, and the time-of-check-time-of-use rule.
  */
class Part10AllocTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <alloca.h>
    |
    |void bad_alloc_from_parsed(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p = (char *)malloc(n);
    |    if (p) free(p);
    |}
    |
    |void bad_alloca_from_parsed(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p = (char *)alloca(n);
    |    if (p) p[0] = 0;
    |}
    |
    |static const int codes[] = {331, 230, 0};
    |
    |int init_local(void)
    |{
    |    char digits[] = {1, 2, 0};
    |    const char *opts[] = {"a", "b", NULL};
    |    return digits[0] + codes[0] + (opts[0] != NULL);
    |}
    |
    |void bad_len_mismatch(const char *userInput)
    |{
    |    size_t n = strlen(userInput);
    |    char *buf = (char *)malloc(n);
    |    if (buf == NULL) return;
    |    strcpy(buf, userInput);
    |    free(buf);
    |}
    |
    |void good_sized(const char *userInput)
    |{
    |    size_t n = strlen(userInput) + 1;
    |    char *buf = (char *)malloc(n);
    |    if (buf == NULL) return;
    |    memcpy(buf, userInput, n);
    |    free(buf);
    |}
    |
    |void good_param_alloc(size_t n)
    |{
    |    char *p = (char *)malloc(n);
    |    if (p) free(p);
    |}
    |
    |int main(void)
    |{
    |    good_param_alloc(16);
    |    return 0;
    |}
    |""".stripMargin,
    "part10alloc.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String, rule: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains(rule)).l

  private def confidenceOf(node: StoredNode, rule: String): String =
      MemorySafetyFindingPass.confidenceOf(node, MemorySafetyFindingPass.rules(rule))

  "the uncontrolled-allocation tiers" should:
    "report a size parsed from attacker input at medium" in {
        val nodes = findingsIn("bad_alloc_from_parsed", "MS-ALLOC-008")
        nodes should not be empty
        nodes.map(confidenceOf(_, "MS-ALLOC-008")) should contain("medium")
    }

    "report an attacker-sized alloca at medium" in {
        val nodes = findingsIn("bad_alloca_from_parsed", "MS-ALLOC-008")
        nodes should not be empty
        nodes.map(confidenceOf(_, "MS-ALLOC-008")) should contain("medium")
    }

    "keep quiet on initialized unknown-bound arrays, static or not" in {
        findingsIn("init_local", "MS-ALLOC-008") shouldBe empty
    }

  "the strlen stand-down" should:
    "keep quiet on malloc(strlen(s))" in {
        findingsIn("bad_len_mismatch", "MS-ALLOC-008") shouldBe empty
    }

    "keep quiet on malloc(strlen(s) + 1)" in {
        findingsIn("good_sized", "MS-ALLOC-008") shouldBe empty
    }

  "the caller-param arm" should:
    "stay quiet when every caller passes a constant" in {
        findingsIn("good_param_alloc", "MS-ALLOC-008") shouldBe empty
    }
end Part10AllocTests

class Part10FoldTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdint.h>
    |#include <string.h>
    |
    |int bad_narrowing_in_guard(uint32_t obu_size, int remaining, unsigned char *dst,
    |                           const unsigned char *src)
    |{
    |    if ((long)obu_size > remaining)
    |        return -1;
    |    memcpy(dst, src, obu_size);
    |    return 0;
    |}
    |""".stripMargin,
    "part10fold.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String, rule: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains(rule)).l

  "the lossy-cast fold" should:
    "report the lossy cast in the guard" in {
        findingsIn("bad_narrowing_in_guard", "MS-INT-002") should not be empty
    }

    "fold the copy finding at the sink into the guard finding" in {
        findingsIn("bad_narrowing_in_guard", "MS-BOUND-002") shouldBe empty
        findingsIn("bad_narrowing_in_guard", "MS-BOUND-001") shouldBe empty
    }
end Part10FoldTests

class Part10ToctouTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdio.h>
    |#include <unistd.h>
    |#include <sys/stat.h>
    |#include <fcntl.h>
    |
    |void bad_access_open(const char *path)
    |{
    |    if (access(path, W_OK) == 0)
    |    {
    |        FILE *f = fopen(path, "w");
    |        if (f) { fputs("data", f); fclose(f); }
    |    }
    |}
    |
    |void bad_stat_open(const char *path)
    |{
    |    struct stat st;
    |    if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
    |    {
    |        int fd = open(path, O_RDWR);
    |        if (fd >= 0) close(fd);
    |    }
    |}
    |
    |void good_openat_fstat(const char *path)
    |{
    |    int fd = open(path, O_RDWR);
    |    struct stat st;
    |    if (fd < 0) return;
    |    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode))
    |    {
    |        (void)write(fd, "data", 4);
    |    }
    |    close(fd);
    |}
    |
    |void good_rebound_path(const char *in)
    |{
    |    char path[256];
    |    if (access(in, R_OK) == 0)
    |    {
    |        snprintf(path, sizeof(path), "%s.tmp", in);
    |        int fd = open(path, O_RDONLY);
    |        if (fd >= 0) close(fd);
    |    }
    |}
    |""".stripMargin,
    "part10toctou.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String, rule: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains(rule)).l

  "the path TOCTOU arm" should:
    "report access then fopen on the same path" in {
        findingsIn("bad_access_open", "MS-TOCTOU-001") should not be empty
    }

    "report stat then open on the same path" in {
        findingsIn("bad_stat_open", "MS-TOCTOU-001") should not be empty
    }

    "stay silent on the open-then-fstat descriptor form" in {
        findingsIn("good_openat_fstat", "MS-TOCTOU-001") shouldBe empty
    }

    "stay silent when the use opens a different path" in {
        findingsIn("good_rebound_path", "MS-TOCTOU-001") shouldBe empty
    }
end Part10ToctouTests

class Part10ToctouCppTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <mutex>
    |
    |static int g_counter = 0;
    |static std::mutex g_mutex;
    |
    |void bad_check_then_act()
    |{
    |    if (g_counter < 10)
    |    {
    |        g_counter += 1;
    |    }
    |}
    |
    |void good_locked()
    |{
    |    std::lock_guard<std::mutex> lk(g_mutex);
    |    g_counter++;
    |}
    |""".stripMargin,
    "part10toctou.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String, rule: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains(rule)).l

  "the shared-global check-then-act arm" should:
    "report a guard that reads a global and a branch that writes it" in {
        findingsIn("bad_check_then_act", "MS-TOCTOU-001") should not be empty
    }

    "stay silent behind a lock" in {
        findingsIn("good_locked", "MS-TOCTOU-001") shouldBe empty
    }
end Part10ToctouCppTests
