package io.appthreat.edg2atom.passes

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.testfixtures.DefaultTestCpgWithEdg
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.taggers.*
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

/** The C object model on the EDG frontend, the shapes the CDT suites check: operations undefined
  * for some operands, objects with offsets and access sizes, paths a call that does not return
  * ends, objects a block ends, and the C library's contracts. EDG's own facts (its type sizes, its
  * VLA bound, its flexible member, `_Noreturn`) feed the same rules.
  */
class MemorySafetyOnEdgObjectModelTests extends Code2CpgFixture(() =>
        new DefaultTestCpgWithEdg(".c")
    ):

  private val edgaAvailable       = EdgaRunner.locate().isDefined
  private def requireEdga(): Unit = assume(edgaAvailable, "edga is not installed")

  private lazy val cpg =
    val graph = code(
      """
      |#include <stdio.h>
      |#include <stdlib.h>
      |#include <string.h>
      |#include <alloca.h>
      |unsigned long good_small_anonymous_union(const unsigned long *a)
      |{
      |    union { unsigned long bn[3]; unsigned int ui[6]; } buf;
      |    int i;
      |    for (i = 0; i < 3; i++) buf.bn[i] = a[i];
      |    return buf.bn[0];
      |}
      |unsigned long good_large_anonymous_union(const unsigned long *a)
      |{
      |    union { unsigned long bn[4]; unsigned int ui[8]; } buf;
      |    int i;
      |    for (i = 0; i < 4; i++) buf.bn[i] = a[i];
      |    return buf.bn[0];
      |}
      |int bad_divide_input(int total)
      |{
      |    char line[32];
      |    int parts;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    parts = atoi(line);
      |    return total / parts; 
      |}
      |int bad_modulo_input(int total)
      |{
      |    char line[32];
      |    int parts;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    parts = atoi(line);
      |    return total % parts; 
      |}
      |double bad_float_divide(void)
      |{
      |    char line[32];
      |    double scale;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0.0;
      |    scale = atof(line);
      |    return 100.0 / scale; 
      |}
      |int bad_divide_by_literal_zero(int total)
      |{
      |    int zero = 0;
      |    return total / zero; 
      |}
      |static int share(int total, int parts)
      |{
      |    return total / parts; 
      |}
      |int bad_divide_through_parameter(int total)
      |{
      |    char line[32];
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    return share(total, atoi(line));
      |}
      |int good_divide_checked(int total)
      |{
      |    char line[32];
      |    int parts;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    parts = atoi(line);
      |    if (parts == 0) return 0;
      |    return total / parts; 
      |}
      |int good_divide_nonzero_guard(int total)
      |{
      |    char line[32];
      |    int parts;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    parts = atoi(line);
      |    if (parts != 0)
      |        return total / parts; 
      |    return 0;
      |}
      |int good_divide_constant(int total)
      |{
      |    return total / 4; 
      |}
      |int good_divide_clamped(int total)
      |{
      |    char line[32];
      |    int parts;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    parts = atoi(line);
      |    if (parts < 1) parts = 1;
      |    return total / parts; 
      |}
      |int good_divide_short_circuit(int total)
      |{
      |    char line[32];
      |    int parts;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    parts = atoi(line);
      |    return parts ? total / parts : 0; 
      |}
      |double good_float_checked(void)
      |{
      |    char line[32];
      |    double scale;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0.0;
      |    scale = atof(line);
      |    if (scale > -0.000001 && scale < 0.000001) return 0.0;
      |    return 100.0 / scale; 
      |}
      |int good_divide_parameter(int total, int parts)
      |{
      |    return total / parts; 
      |}
      |unsigned bad_shift_by_input(unsigned value)
      |{
      |    char line[32];
      |    int amount;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    amount = atoi(line);
      |    return value << amount; 
      |}
      |unsigned bad_shift_by_width(unsigned value)
      |{
      |    int amount = 32;
      |    return value >> amount; 
      |}
      |int bad_shift_negative_amount(int value)
      |{
      |    int amount = -1;
      |    return value << amount; 
      |}
      |unsigned good_shift_masked(unsigned value)
      |{
      |    char line[32];
      |    int amount;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    amount = atoi(line) & 31;
      |    return value << amount; 
      |}
      |unsigned good_shift_checked(unsigned value)
      |{
      |    char line[32];
      |    int amount;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    amount = atoi(line);
      |    if (amount < 0 || amount >= 32) return 0;
      |    return value << amount; 
      |}
      |long long good_shift_converted(int value)
      |{
      |    return ((long long)value) << 32;
      |}
      |unsigned long long good_shift_wide(unsigned long long value)
      |{
      |    int amount = 40;
      |    return value << amount; 
      |}
      |unsigned good_shift_parameter(unsigned value, int amount)
      |{
      |    return value << amount; 
      |}
      |size_t bad_index_in_other_string(void)
      |{
      |    char first[] = "a/b";
      |    char second[] = "a/b";
      |    char *slash = strchr(first, '/');
      |    if (slash == NULL) return 0;
      |    return (size_t)(slash - second); 
      |}
      |long bad_distance_between_locals(void)
      |{
      |    char head[16];
      |    char tail[16];
      |    return tail - head; 
      |}
      |size_t good_index_in_same_string(void)
      |{
      |    char first[] = "a/b";
      |    char *slash = strchr(first, '/');
      |    if (slash == NULL) return 0;
      |    return (size_t)(slash - first); 
      |}
      |size_t good_end_minus_start(void)
      |{
      |    char line[32] = "abc";
      |    char *end = line + strlen(line);
      |    return (size_t)(end - line); 
      |}
      |long good_parameters(const char *a, const char *b)
      |{
      |    return b - a; 
      |}
      |void bad_memcpy_overlap(void)
      |{
      |    char data[32] = "0123456789abcdefghij";
      |    memcpy(data + 6, data + 4, 10); 
      |    puts(data);
      |}
      |void bad_memcpy_onto_itself_shifted(char *line)
      |{
      |    char buf[64];
      |    strncpy(buf, line, 63);
      |    buf[63] = '\0';
      |    memcpy(buf, buf + 1, 32); 
      |    puts(buf);
      |}
      |void bad_strcpy_overlap(void)
      |{
      |    char text[32] = "hello world";
      |    strcpy(text + 2, text); 
      |    puts(text);
      |}
      |void good_memmove_overlap(void)
      |{
      |    char data[32] = "0123456789abcdefghij";
      |    memmove(data + 6, data + 4, 10); 
      |    puts(data);
      |}
      |void good_memcpy_disjoint(void)
      |{
      |    char data[32] = "0123456789abcdefghij";
      |    memcpy(data + 16, data, 10); 
      |    puts(data);
      |}
      |void good_memcpy_two_buffers(void)
      |{
      |    char src[16] = "abc";
      |    char dst[16];
      |    memcpy(dst, src, sizeof(src)); 
      |    puts(dst);
      |}
      |void bad_underwrite(void)
      |{
      |    char buf[16];
      |    char *p = buf;
      |    p[-1] = '\0'; 
      |}
      |char bad_underread(void)
      |{
      |    char buf[16] = "abc";
      |    char *p = &buf[2];
      |    return p[-3]; 
      |}
      |void good_back_one(void)
      |{
      |    char buf[16];
      |    char *p = buf + 4;
      |    p[-1] = '\0'; 
      |}
      |void bad_offset_overrun(void)
      |{
      |    char buf[16];
      |    char *p = buf + 12;
      |    memset(p, 0, 8); 
      |}
      |void good_offset_fits(void)
      |{
      |    char buf[16];
      |    char *p = buf + 8;
      |    memset(p, 0, 8); 
      |}
      |void bad_element_bytes(void)
      |{
      |    int counts[10];
      |    memset(counts, 0, 44); 
      |}
      |void good_element_bytes(void)
      |{
      |    int counts[10];
      |    memset(counts, 0, sizeof(counts)); 
      |}
      |void bad_vla_copy(size_t n, const char *user)
      |{
      |    char buf[n];
      |    strcpy(buf, user); 
      |}
      |void bad_vla_index(size_t n, const char *user)
      |{
      |    char buf[n];
      |    size_t i = n;
      |    buf[i] = '\0'; 
      |}
      |void good_vla_copy(size_t n, const char *user)
      |{
      |    char buf[n];
      |    strncpy(buf, user, n); 
      |    buf[n - 1] = '\0';
      |}
      |struct msg {
      |    size_t len;
      |    char data[];
      |};
      |void bad_fam_copy(size_t n, const char *user)
      |{
      |    struct msg *m = malloc(sizeof(*m) + n);
      |    if (!m) return;
      |    strcpy(m->data, user); 
      |    free(m);
      |}
      |void bad_fam_alloc(size_t n, const char *user)
      |{
      |    struct msg *m = malloc(sizeof(*m)); 
      |    if (!m) return;
      |    memcpy(m->data, user, n); 
      |    free(m);
      |}
      |void good_fam_copy(size_t n, const char *user)
      |{
      |    struct msg *m = malloc(sizeof(*m) + n);
      |    if (!m) return;
      |    memcpy(m->data, user, n); 
      |    free(m);
      |}
      |
      |void print_int(int value);
      |struct pair { int one; int two; };
      |void print_pair(struct pair *p);
      |void bad_wider_read(void) {
      |    void *data = NULL;
      |    char c = 'a';
      |    data = &c;
      |    print_int(*((int *)data));
      |}
      |void good_same_width(void) {
      |    void *data = NULL;
      |    int v = 8;
      |    data = &v;
      |    print_int(*((int *)data));
      |}
      |void bad_struct_of_int(void) {
      |    int value = 100;
      |    print_pair((struct pair *)&value);
      |}
      |void good_struct_of_struct(void) {
      |    struct pair p = {1, 2};
      |    print_pair((struct pair *)&p);
      |}
      |_Noreturn static void bail(const char *why) {
      |    fprintf(stderr, "%s\n", why);
      |    abort();
      |}
      |__attribute__((noreturn)) void die(int code);
      |static void warn(const char *why) {
      |    fprintf(stderr, "%s\n", why);
      |}
      |void bad_dead_reset(int n, const char *user) {
      |    char buf[8];
      |    if (n < 0) {
      |        bail(user);
      |        n = 0;
      |    }
      |    buf[n] = 'x';
      |}
      |void good_exit_guard(int n, const char *user) {
      |    char buf[8];
      |    if (n < 0 || n >= 8) {
      |        bail(user);
      |    }
      |    buf[n] = 'x';
      |}
      |void good_attribute_guard(int n) {
      |    char buf[8];
      |    if (n < 0 || n >= 8) die(1);
      |    buf[n] = 'x';
      |}
      |void bad_returning_helper(int n, const char *user) {
      |    char buf[8];
      |    if (n < 0 || n >= 8) {
      |        warn(user);
      |    }
      |    buf[n] = 'x';
      |}
      |int after_exit(int x) {
      |    exit(x);
      |    return x + 1;
      |}
      |int bad_inner_block_address(int flag)
      |{
      |    int *p = NULL;
      |    if (flag) {
      |        int inner = 42;
      |        p = &inner;
      |    }
      |    return p ? *p : 0; 
      |}
      |int bad_inner_array(int i)
      |{
      |    char *view;
      |    {
      |        char buf[16] = "scoped";
      |        view = buf;
      |    }
      |    return view[i & 7]; 
      |}
      |int bad_inner_compound_literal(int x)
      |{
      |    int *pair;
      |    {
      |        pair = (int[]){x, x + 1};
      |    }
      |    return pair[1]; 
      |}
      |int good_same_block(int flag)
      |{
      |    int outer = 7;
      |    int *p = &outer;
      |    if (flag) {
      |        int inner = 42;
      |        p = &inner;
      |        return *p; 
      |    }
      |    return *p; 
      |}
      |int good_outer_array(int i)
      |{
      |    char buf[16] = "outer";
      |    char *view;
      |    {
      |        view = buf;
      |    }
      |    return view[i & 7]; 
      |}
      |int good_static_inner(int flag) {
      |    int *p = NULL;
      |    if (flag) {
      |        static int kept = 3;
      |        p = &kept;
      |    }
      |    return p ? *p : 0;
      |}
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
      |void good_calloc_product(size_t n) { int *p = calloc(n, sizeof(int)); free(p); }
      |""".stripMargin,
      "object_model.c"
    )
    X2Cpg.applyDefaultOverlays(graph)
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(graph))
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

  private def check(rule: String, bad: Seq[String], good: Seq[String]): Unit =
    requireEdga()
    bad.foreach(m => withClue(m) { findingsIn(m) should contain(rule) })
    good.foreach(m => withClue(m) { findingsIn(m) should not contain rule })

  "the undefined operations" should {
      "report division, shift, pointer difference and overlap as the CDT suite does" in {
          check(
            "MS-DIV-001",
            Seq(
              "bad_divide_input",
              "bad_modulo_input",
              "bad_float_divide",
              "bad_divide_by_literal_zero",
              "share"
            ),
            Seq(
              "good_divide_checked",
              "good_divide_nonzero_guard",
              "good_divide_constant",
              "good_divide_clamped",
              "good_divide_short_circuit",
              "good_float_checked",
              "good_divide_parameter"
            )
          )
          check(
            "MS-SHIFT-001",
            Seq("bad_shift_by_input", "bad_shift_by_width", "bad_shift_negative_amount"),
            Seq(
              "good_shift_masked",
              "good_shift_checked",
              "good_shift_wide",
              "good_shift_parameter",
              "good_shift_converted"
            )
          )
          check(
            "MS-PTR-001",
            Seq("bad_index_in_other_string", "bad_distance_between_locals"),
            Seq("good_index_in_same_string", "good_end_minus_start", "good_parameters")
          )
          check(
            "MS-OVERLAP-001",
            Seq("bad_memcpy_overlap", "bad_memcpy_onto_itself_shifted", "bad_strcpy_overlap"),
            Seq("good_memmove_overlap", "good_memcpy_disjoint", "good_memcpy_two_buffers")
          )
      }
  }

  "an object and an offset" should {
      "bound accesses before the object, past a view's room, in bytes, by a VLA bound and a flexible member's room" in {
          requireEdga()
          findingsIn("bad_underwrite") should contain("MS-BOUND-009")
          findingsIn("bad_underread") should contain("MS-BOUND-010")
          findingsIn("bad_offset_overrun") should contain("MS-BOUND-006")
          findingsIn("bad_element_bytes") should contain("MS-BOUND-006")
          findingsIn("bad_vla_index") should contain("MS-BOUND-004")
          findingsIn("bad_vla_copy").exists(_.startsWith("MS-BOUND")) shouldBe true
          findingsIn("bad_fam_copy").exists(_.startsWith("MS-BOUND")) shouldBe true
          findingsIn("bad_fam_alloc").exists(_.startsWith("MS-BOUND")) shouldBe true
          findingsIn("bad_wider_read") should contain("MS-BOUND-003")
          findingsIn("bad_struct_of_int") should contain("MS-BOUND-003")
          Seq(
            "good_back_one",
            "good_offset_fits",
            "good_element_bytes",
            "good_vla_copy",
            "good_fam_copy",
            "good_same_width",
            "good_struct_of_struct"
          ).foreach { m =>
              withClue(m) { findingsIn(m).filter(_.startsWith("MS-BOUND")) shouldBe Set.empty }
          }
      }
  }

  "a call that does not return" should {
      "end its path on EDG's own noreturn fact" in {
          requireEdga()
          findingsIn("bad_dead_reset") should contain("MS-BOUND-004")
          findingsIn("good_exit_guard") shouldBe Set.empty
          findingsIn("good_attribute_guard") shouldBe Set.empty
          findingsIn("bad_returning_helper") should contain("MS-BOUND-004")
      }
  }

  "an object a block ends" should {
      "be dead after the block" in {
          check(
            "MS-ALLOC-002",
            Seq("bad_inner_block_address", "bad_inner_array", "bad_inner_compound_literal"),
            Seq("good_same_block", "good_outer_array", "good_static_inner")
          )
      }
  }

  "the library's contracts" should {
      "read each anonymous union's own member bound" in {
          requireEdga()
          findingsIn("good_large_anonymous_union") shouldBe Set.empty
      }
      "hold for release, realloc and length-bounded writers" in {
          requireEdga()
          findingsIn("bad_free_alloca") shouldBe Set("MS-ALLOC-005")
          findingsIn("bad_free_local_address") should contain("MS-ALLOC-005")
          findingsIn("bad_realloc_static") should contain("MS-ALLOC-005")
          findingsIn("bad_realloc_in_place") should contain("MS-ALLOC-003")
          findingsIn("good_realloc_through_temporary") shouldBe Set.empty
          Seq("bad_fgets_size", "bad_snprintf_size", "bad_strncpy_size", "bad_memset_size").foreach {
              m => withClue(m) { findingsIn(m) should contain("MS-BOUND-006") }
          }
          findingsIn("good_fgets_size") shouldBe Set.empty
      }
  }
end MemorySafetyOnEdgObjectModelTests
