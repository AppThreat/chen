package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** The C library's contracts, as CBMC's library models state them: what free and realloc may be
  * handed (heap storage at its start, of their own family), what a failed realloc leaves, and the
  * destination a length-bounded reader or writer must hold.
  */
class LibraryContractTests extends DataFlowCodeToCpgSuite:
  private val sourceCpg = code(
    """
      |#include <stdlib.h>
      |#include <string.h>
      |#include <stdio.h>
      |void *alloca(size_t);
      |void bad_free_alloca(void)
      |{
      |    char *p = alloca(32);
      |    memset(p, 0, 32);
      |    free(p); 
      |}
      |void bad_free_local_address(void)
      |{
      |    int value = 0;
      |    int *p = &value;
      |    free(p); 
      |}
      |void bad_realloc_static(void)
      |{
      |    static char buf[8];
      |    char *grown = realloc(buf, 16); 
      |    free(grown);
      |}
      |void good_free_heap_copy(void)
      |{
      |    char *p = malloc(8);
      |    char *q = p;
      |    free(q); 
      |}
      |void good_free_either_heap(int flag)
      |{
      |    char *p = flag ? malloc(8) : malloc(16);
      |    free(p); 
      |}
      |char *bad_realloc_in_place(void)
      |{
      |    char *p = malloc(16);
      |    if (p == NULL) return NULL;
      |    p = realloc(p, 64); 
      |    return p;
      |}
      |char *good_realloc_through_temporary(void)
      |{
      |    char *p = malloc(16);
      |    char *grown;
      |    if (p == NULL) return NULL;
      |    grown = realloc(p, 64); 
      |    if (grown == NULL) {
      |        free(p);
      |        return NULL;
      |    }
      |    return grown;
      |}
      |void bad_fgets_size(FILE *f) { char buf[16]; fgets(buf, 32, f); }
      |void good_fgets_size(FILE *f) { char buf[16]; fgets(buf, sizeof(buf), f); }
      |void bad_snprintf_size(const char *s) { char buf[16]; snprintf(buf, 32, "%s", s); }
      |void bad_strncpy_size(const char *s) { char buf[16]; strncpy(buf, s, 20); }
      |void bad_memset_size(void) { char buf[16]; memset(buf, 0, 17); }
      |long read(int fd, void *buf, size_t n);
      |long good_read_into_callers_buffer(size_t n, char *scratch, int fd) { return read(fd, scratch, n); }
      |void good_calloc_product(size_t n) { int *p = calloc(n, sizeof(int)); free(p); }
      |typedef unsigned int socklen_t;
      |struct sockaddr;
      |long recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *from, socklen_t *fromlen);
      |struct peer { char addr[128]; };
      |void good_reported_address_length(int fd, struct peer *p)
      |{
      |    char packet[512];
      |    char from[128];
      |    socklen_t fromlen = sizeof(from);
      |    if (recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)from, &fromlen) < 0)
      |        return;
      |    memcpy(p->addr, from, fromlen);
      |}
      |void bad_scanned_length(struct peer *p, const char *from)
      |{
      |    int n;
      |    if (scanf("%d", &n) != 1)
      |        return;
      |    memcpy(p->addr, from, n);
      |}
      |void copy_ignoring_capacity(char *dst, size_t cap, int fd)
      |{
      |    char tmp[64];
      |    long n = read(fd, tmp, sizeof(tmp));
      |    memcpy(dst, tmp, n);
      |}
      |""".stripMargin,
    "library.c"
  )
  private lazy val cpg =
    val graph = sourceCpg
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new ExtentPass(graph).createAndApply()
    new GuardPass(graph).createAndApply()
    new ValueOriginPass(graph).createAndApply()
    new IntegerWidthPass(graph).createAndApply()
    new AllocationStatePass(graph).createAndApply()
    new MemorySafetyFindingPass(graph).createAndApply()
    graph
  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "a release" should {
      "report stack, a local's address and static storage handed to free or realloc" in {
          findingsIn("bad_free_alloca") shouldBe Set("MS-ALLOC-005")
          findingsIn("bad_free_local_address") should contain("MS-ALLOC-005")
          findingsIn("bad_realloc_static") should contain("MS-ALLOC-005")
      }
      "stay silent for heap storage" in {
          findingsIn("good_free_heap_copy") shouldBe Set.empty
          findingsIn("good_free_either_heap") shouldBe Set.empty
      }
  }

  "a realloc" should {
      "report the block lost when it fails into its own handle" in {
          findingsIn("bad_realloc_in_place") should contain("MS-ALLOC-003")
      }
      "release its input only where it succeeded" in {
          findingsIn("good_realloc_through_temporary") shouldBe Set.empty
      }
  }

  "a length-bounded reader or writer" should {
      "report a length past the destination" in {
          Seq("bad_fgets_size", "bad_snprintf_size", "bad_strncpy_size", "bad_memset_size").foreach {
              m => withClue(m) { findingsIn(m) should contain("MS-BOUND-006") }
          }
          findingsIn("good_fgets_size") shouldBe Set.empty
          findingsIn("good_read_into_callers_buffer") shouldBe Set.empty
      }
  }

  "a reader's outputs" should {
      "be input only through the argument the reader fills" in {
          findingsIn("good_reported_address_length") should not contain "MS-BOUND-002"
          findingsIn("bad_scanned_length") should contain("MS-BOUND-002")
      }
  }

  "a copy that ignores its destination's capacity parameter" should {
      "be reported once, as the capacity contract" in {
          findingsIn("copy_ignoring_capacity") should contain("MS-BOUND-001")
          findingsIn("copy_ignoring_capacity") should not contain "MS-BOUND-002"
      }
  }

  "calloc" should {
      "not be an overflow site: it checks its own product" in {
          findingsIn("good_calloc_product").filter(r =>
              r == "MS-INT-001" || r == "MS-ALLOC-009"
          ) shouldBe
              Set.empty
      }
  }
end LibraryContractTests
