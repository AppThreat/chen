package io.appthreat.edg2atom.passes

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.testfixtures.DefaultTestCpgWithEdg
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.taggers.*
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.codepropertygraph.generated.nodes.{Call, StoredNode}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

class EdgResolvedFactsCpg extends DefaultTestCpgWithEdg(".cpp"):
  override protected def applyPasses(): Unit =
    X2Cpg.applyDefaultOverlays(this)
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(this))

/** The graph edga gives over the same shapes the round's fixes target: a resolved overload's own
  * summary at its call, a lambda instance named apart from its call, an implicit member's declared
  * extent, and an anonymous member's owner-qualified name.
  */
class MemorySafetyOnEdgResolvedFactsTests extends Code2CpgFixture(() => new EdgResolvedFactsCpg()):

  private val edgaAvailable = EdgaRunner.locate().isDefined

  private lazy val cpg =
    val graph = code(
      """
      |#include <cstddef>
      |#include <cstdio>
      |#include <cstdlib>
      |#include <cstring>
      |#include <cwchar>
      |#include <string>
      |
      |static void copy_into(char *dst, const char *src) {
      |    strcpy(dst, src);
      |}
      |static void copy_into(std::string &dst, const char *src) {
      |    dst = src;
      |}
      |void bad_overload_copy(const char *user) {
      |    char buf[16];
      |    copy_into(buf, user);
      |}
      |
      |static auto copy_len = [](char *dst, const char *src, size_t n) {
      |    memcpy(dst, src, n);
      |};
      |void bad_lambda_length(const char *user) {
      |    char buf[16];
      |    copy_len(buf, user, 64);
      |}
      |void good_lambda_length(const char *user) {
      |    char buf[16];
      |    copy_len(buf, user, 8);
      |}
      |
      |void bad_walk_then_free(char *data) {
      |    for (; *data != '\0'; data++) {
      |        if (*data == 'x') break;
      |    }
      |    free(data);
      |}
      |void good_walk_a_copy(char *data) {
      |    char *cursor = data;
      |    for (; *cursor != '\0'; cursor++) {
      |        if (*cursor == 'x') break;
      |    }
      |    free(data);
      |}
      |
      |void bad_double_free() {
      |    char *p = (char *)malloc(100);
      |    if (p == NULL) exit(-1);
      |    free(p);
      |    free(p);
      |}
      |void good_free_once() {
      |    char *p = (char *)malloc(100);
      |    if (p == NULL) exit(-1);
      |    free(p);
      |}
      |
      |void bad_new_count_lower_bound() {
      |    size_t data = 0;
      |    char inputBuffer[20] = "";
      |    if (fgets(inputBuffer, 20, stdin) != NULL) data = strtoul(inputBuffer, NULL, 0);
      |    if (data > strlen("hello")) {
      |        char *p = new char[data];
      |        strcpy(p, "hello");
      |        delete[] p;
      |    }
      |}
      |void good_new_count_capped() {
      |    size_t data = 0;
      |    char inputBuffer[20] = "";
      |    if (fgets(inputBuffer, 20, stdin) != NULL) data = strtoul(inputBuffer, NULL, 0);
      |    if (data > strlen("hello") && data < 1000) {
      |        char *p = new char[data];
      |        strcpy(p, "hello");
      |        delete[] p;
      |    }
      |}
      |void bad_scanf_size_after_init() {
      |    size_t data = 0;
      |    fscanf(stdin, "%zu", &data);
      |    char *p = (char *)malloc(data * sizeof(char));
      |    if (p) free(p);
      |}
      |void good_strlen_size_after_init(const char *s) {
      |    size_t data = 0;
      |    data = strlen(s);
      |    char *p = (char *)malloc(data * sizeof(char));
      |    if (p) free(p);
      |}
      |void bad_new_overflowed_bytes() {
      |    int data = -1;
      |    char inputBuffer[20] = "";
      |    if (fgets(inputBuffer, 20, stdin) != NULL) data = atoi(inputBuffer);
      |    size_t dataBytes = data * sizeof(int);
      |    int *intPointer = (int *)new char[dataBytes];
      |    for (size_t i = 0; i < (size_t)data; i++) {
      |        intPointer[i] = 0;
      |    }
      |    delete[] intPointer;
      |}
      |
      |void bad_overread_alias_strlen()
      |{
      |    char *data;
      |    char small[50];
      |    char big[100];
      |    char dest[100];
      |    memset(small, 'A', 49);
      |    small[49] = '\0';
      |    memset(big, 'C', 99);
      |    big[99] = '\0';
      |    data = small;
      |    size_t i, destLen;
      |    memset(dest, 'C', 99);
      |    dest[99] = '\0';
      |    destLen = strlen(dest);
      |    for (i = 0; i < destLen; i++)
      |    {
      |        dest[i] = data[i];
      |    }
      |}
      |
      |void good_overread_alias_strlen()
      |{
      |    char *data;
      |    char big[100];
      |    char dest[100];
      |    memset(big, 'A', 99);
      |    big[99] = '\0';
      |    data = big;
      |    size_t i, destLen;
      |    memset(dest, 'C', 99);
      |    dest[99] = '\0';
      |    destLen = strlen(dest);
      |    for (i = 0; i < destLen; i++)
      |    {
      |        dest[i] = data[i];
      |    }
      |}
      |
      |void bad_overread_alias_wcslen()
      |{
      |    wchar_t *data;
      |    wchar_t small[50];
      |    wchar_t dest[100];
      |    wmemset(small, L'A', 49);
      |    small[49] = L'\0';
      |    data = small;
      |    size_t i, destLen;
      |    wmemset(dest, L'C', 99);
      |    dest[99] = L'\0';
      |    destLen = wcslen(dest);
      |    for (i = 0; i < destLen; i++)
      |    {
      |        dest[i] = data[i];
      |    }
      |}
      |
      |void good_overread_alias_wcslen()
      |{
      |    wchar_t *data;
      |    wchar_t big[100];
      |    wchar_t dest[100];
      |    wmemset(big, L'A', 99);
      |    big[99] = L'\0';
      |    data = big;
      |    size_t i, destLen;
      |    wmemset(dest, L'C', 99);
      |    dest[99] = L'\0';
      |    destLen = wcslen(dest);
      |    for (i = 0; i < destLen; i++)
      |    {
      |        dest[i] = data[i];
      |    }
      |}

      |struct table_t {
      |    char slots[4];
      |    char &operator[](int i) { return slots[i]; }
      |};
      |void bad_table_index(const char *user) {
      |    table_t t;
      |    int idx = atoi(user);
      |    t[idx] = 'x';
      |}
      |""".stripMargin,
      "resolved.cpp"
    )
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new ExtentPass(graph).createAndApply()
    new GuardPass(graph).createAndApply()
    new ValueOriginPass(graph).createAndApply()
    new IntegerWidthPass(graph).createAndApply()
    new AllocationStatePass(graph).createAndApply()
    new MemorySafetyFindingPass(graph).createAndApply()
    graph
  end cpg

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  private def findingsOf(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  if edgaAvailable then
    "a call EDG resolved to the copying overload" should {
        "overrun the caller's buffer at the call" in {
            findingsIn("bad_overload_copy") should contain("MS-BOUND-006")
        }
    }

    "a lambda instance's own summary" should {
        "apply at the call spelled with the lambda's variable" in {
            findingsIn("bad_lambda_length") should contain("MS-BOUND-006")
            findingsIn("good_lambda_length") should not contain "MS-BOUND-006"
        }
    }

    "a pointer walked by a loop and then freed" should {
        "be reported at the walk's increment" in {
            val walks = cpg.method.nameExact("bad_walk_then_free").ast.collectAll[StoredNode]
                .filter(_.tag.nameExact("ms-finding").value.l.contains("MS-ALLOC-006"))
                .collectAll[Call].l
            walks.map(_.code) shouldBe List("data++")
            findingsIn("good_walk_a_copy") should not contain "MS-ALLOC-006"
        }
    }

    "a double free" should {
        "be reported at both releases" in {
            val sites = cpg.method.nameExact("bad_double_free").ast.collectAll[io.shiftleft.codepropertygraph.generated.nodes.AstNode]
                .filter(_.tag.nameExact("ms-finding").value.l.contains("MS-ALLOC-001")).l
            sites.flatMap(_.lineNumber).map(_.toInt).distinct.size shouldBe 2
            findingsIn("good_free_once") should not contain "MS-ALLOC-001"
        }
    }

    "an allocation size the program reads" should {
        "be uncontrolled when only a lower bound or a scanf-filled definition stands" in {
            findingsIn("bad_new_count_lower_bound") should contain("MS-ALLOC-008")
            findingsIn("good_new_count_capped") should not contain "MS-ALLOC-008"
            findingsIn("bad_scanf_size_after_init") should contain("MS-ALLOC-008")
            findingsIn("good_strlen_size_after_init") should not contain "MS-ALLOC-008"
        }
        "overrun a new[] sized by overflowed arithmetic at the write" in {
            findingsIn("bad_new_overflowed_bytes") should contain("MS-BOUND-007")
        }
    }

    "a loop bounded by a string's length over a pointer to a smaller buffer" should {
        "report the read of the smaller buffer and stay silent on the larger" in {
            findingsIn("bad_overread_alias_strlen") should contain("MS-BOUND-003")
            findingsIn("good_overread_alias_strlen") should not contain "MS-BOUND-003"
            findingsIn("bad_overread_alias_wcslen") should contain("MS-BOUND-003")
            findingsIn("good_overread_alias_wcslen") should not contain "MS-BOUND-003"
        }
    }

    "an operator's member index with an unbounded caller" should {
        "read out of bounds inside the operator" in {
            findingsOf("operator []") should contain("MS-BOUND-003")
        }
    }
end MemorySafetyOnEdgResolvedFactsTests
