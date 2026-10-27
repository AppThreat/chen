package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    IntegerWidthPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    MemorySemanticsPass,
    ValueOriginPass
}
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Arithmetic on values the program reads, allocation object sizes, and the releases the C++ forms
  * spell: each bad shape has a twin the program makes safe - a guard, a clamp, a wide accumulator,
  * a value-initialiser, a cursor the walk leaves behind.
  */
class ReadValueArithmeticTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <stdio.h>
      |#include <stdlib.h>
      |#include <string.h>
      |#include <limits.h>
      |
      |int bad_constant_add(void)
      |{
      |    int data = 2147483647;
      |    return data + 1;
      |}
      |int bad_constant_unary_minus(void)
      |{
      |    int x = -2147483648;
      |    return -x;
      |}
      |int bad_input_add(FILE *f)
      |{
      |    int data = 0;
      |    if (fscanf(f, "%d", &data) != 1) return 0;
      |    return data + 1;
      |}
      |int good_guarded_add(FILE *f)
      |{
      |    int data = 0;
      |    if (fscanf(f, "%d", &data) != 1) return 0;
      |    if (data > INT_MAX - 1) return 0;
      |    return data + 1;
      |}
      |long long good_wide_add(FILE *f)
      |{
      |    int data = 0;
      |    if (fscanf(f, "%d", &data) != 1) return 0;
      |    return (long long)data + 1;
      |}
      |int good_strlen_remainder(char *s)
      |{
      |    char buf[64];
      |    size_t n = strlen(s);
      |    if (n > 60) return 0;
      |    memcpy(buf, s, 100 - n);
      |    return buf[0];
      |}
      |char bad_truncate_input(FILE *f)
      |{
      |    int data = 0;
      |    if (fscanf(f, "%d", &data) != 1) return 0;
      |    return (char)data;
      |}
      |char bad_truncate_constant(void)
      |{
      |    int data = 2551;
      |    return (char)data;
      |}
      |char good_truncate_clamped(FILE *f)
      |{
      |    int data = 0;
      |    if (fscanf(f, "%d", &data) != 1) return 0;
      |    if (data < 0) data = 0;
      |    if (data > 127) data = 127;
      |    return (char)data;
      |}
      |size_t bad_widening_is_not_truncation(FILE *f)
      |{
      |    int data = 0;
      |    if (fscanf(f, "%d", &data) != 1) return 0;
      |    return (size_t)data;
      |}
      |char *bad_negative_size_malloc(FILE *f)
      |{
      |    int data = 0;
      |    if (fscanf(f, "%d", &data) != 1) return 0;
      |    if (data < 100)
      |        return (char *)malloc(data);
      |    return NULL;
      |}
      |void good_nonnegative_size(FILE *f)
      |{
      |    char source[100], dest[100];
      |    int data = 0;
      |    memset(source, 'A', 99); source[99] = 0;
      |    if (fscanf(f, "%d", &data) != 1) return;
      |    if (data < 0 || data > 100) return;
      |    memcpy(dest, source, data);
      |}
      |int bad_loop_over_alloca(void)
      |{
      |    char *data = (char *)alloca(50);
      |    char source[100];
      |    memset(source, 'A', 99); source[99] = 0;
      |    for (int i = 0; i < 100; i++)
      |        data[i] = source[i];
      |    return data[0];
      |}
      |int good_loop_within_alloca(void)
      |{
      |    char *data = (char *)alloca(100);
      |    char source[100];
      |    memset(source, 'A', 99); source[99] = 0;
      |    for (int i = 0; i < 50; i++)
      |        data[i] = source[i];
      |    return data[0];
      |}
      |int bad_element_size_mismatch(void)
      |{
      |    int *data = (int *)malloc(10);
      |    for (int i = 0; i < 10; i++)
      |        data[i] = i;
      |    return data[0];
      |}
      |int bad_read_before_write(void)
      |{
      |    int *data;
      |    int v;
      |    data = (int *)malloc(10 * sizeof(int));
      |    v = data[3];
      |    return v;
      |}
      |int good_read_after_write(void)
      |{
      |    int *data = (int *)malloc(10 * sizeof(int));
      |    memset(data, 0, 10 * sizeof(int));
      |    return data[3];
      |}
      |int good_value_initialised(void)
      |{
      |    int *data = new int[10]();
      |    (void)data;
      |    return 0;
      |}
      |void bad_free_of_declared_array(void)
      |{
      |    static char dataBuf[100];
      |    char *data;
      |    data = dataBuf;
      |    free(data);
      |}
      |void bad_free_after_walk(char *data)
      |{
      |    for (; *data != '\0'; data++)
      |        ;
      |    free(data);
      |}
      |void good_free_of_cursor(char *data)
      |{
      |    char *cursor;
      |    for (cursor = data; *cursor != '\0'; cursor++)
      |        ;
      |    free(data);
      |}
      |int bad_definite_null(int seed)
      |{
      |    int *p;
      |    int v;
      |    p = NULL;
      |    v = *p + seed;
      |    return v;
      |}
      |int good_zero_the_tail(int *out, const int *src, int n)
      |{
      |    int buf[4];
      |    int i;
      |    for (i = 0; i < n; i++)
      |        out[i] = src[i];
      |    for (; i < 4; i++)
      |        buf[i] = 0;
      |    return buf[0];
      |}
      |#define MAXBITCHUNK ((size_t)1 << (sizeof(size_t) * 8 - 4))
      |size_t good_unsigned_macro_product(void)
      |{
      |    return MAXBITCHUNK * 8;
      |}
      |unsigned bad_complement_shift(FILE *f)
      |{
      |    unsigned bits;
      |    if (fscanf(f, "%u", &bits) != 1 || bits > 32)
      |        return 0;
      |    if (bits != 32)
      |        return 0xffffffffu << (32 - bits);
      |    return 0;
      |}
      |unsigned good_complement_shift(FILE *f)
      |{
      |    unsigned bits;
      |    if (fscanf(f, "%u", &bits) != 1)
      |        return 0;
      |    if (bits > 32)
      |        return 0;
      |    if (bits && bits != 32)
      |        return 0xffffffffu << (32 - bits);
      |    return 0;
      |}
      |""".stripMargin,
    "read_values.c"
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

  private def check(rule: String, bad: Seq[String], good: Seq[String]): Unit =
    bad.foreach(m => withClue(m) { findingsIn(m) should contain(rule) })
    good.foreach(m => withClue(m) { findingsIn(m) should not contain rule })

  "arithmetic on read values" should {
      "report the constant wrap and the unguarded input wrap" in {
          check(
            "MS-INT-003",
            Seq("bad_constant_add", "bad_input_add"),
            Seq("good_guarded_add", "good_wide_add", "good_strlen_remainder")
          )
          findingsIn("bad_constant_unary_minus") should contain("MS-INT-004")
      }
      "report the narrowing conversion, not the widening" in {
          check(
            "MS-CONV-001",
            Seq("bad_truncate_input", "bad_truncate_constant"),
            Seq("good_truncate_clamped", "bad_widening_is_not_truncation")
          )
      }
      "report a negative signed value in an unsigned size position" in {
          check(
            "MS-CONV-002",
            Seq("bad_negative_size_malloc"),
            Seq("good_nonnegative_size")
          )
      }
  }

  "allocation object sizes" should {
      "report the constant loop bound the base cannot hold" in {
          check(
            "MS-BOUND-007",
            Seq("bad_loop_over_alloca", "bad_element_size_mismatch"),
            Seq("good_loop_within_alloca")
          )
      }
      "report a heap array read before any element is written" in {
          check(
            "MS-INIT-001",
            Seq("bad_read_before_write"),
            Seq("good_read_after_write")
          )
      }
      "keep the value-initialised array quiet" in {
          findingsIn("good_value_initialised") should not contain "MS-INIT-001"
      }
  }

  "releases the C++ forms spell" should {
      "report the free of storage the def walk names" in {
          check(
            "MS-ALLOC-005",
            Seq("bad_free_of_declared_array"),
            Seq("good_free_of_cursor")
          )
      }
      "report the walk that moved the freed pointer, at both ends" in {
          check(
            "MS-ALLOC-006",
            Seq("bad_free_after_walk"),
            Seq("good_free_of_cursor")
          )
      }
      "bound a loop write by its own loop's test, not another loop's" in {
          check("MS-BOUND-006", Nil, Seq("good_zero_the_tail"))
      }
      "keep a product computed at size_t quiet" in {
          check("MS-INT-003", Nil, Seq("good_unsigned_macro_product"))
      }
      "read a truthiness test as excluding the complement shift's zero" in {
          check("MS-SHIFT-001", Seq("bad_complement_shift"), Seq("good_complement_shift"))
      }
      "report the definite NULL dereference" in {
          check("MS-NULL-001", Seq("bad_definite_null"), Seq("good_loop_within_alloca"))
      }
  }
end ReadValueArithmeticTests
