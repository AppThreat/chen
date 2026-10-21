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

/** The operations C leaves undefined for some operands: division by zero, the undefined shift, the
  * difference of pointers into two objects, and the overlapping copy the library forbids. Each bad
  * shape has a twin the program makes safe - a guard, a clamp, a mask, one object.
  */
class UndefinedOperationRulesTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <stdio.h>
      |#include <stdlib.h>
      |#include <string.h>
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
      |int bad_divide_scanned(int total)
      |{
      |    int parts = -1;
      |    fscanf(stdin, "%d", &parts);
      |    return total / parts;
      |}
      |#include <wchar.h>
      |size_t bad_wide_index_in_other_string(void)
      |{
      |    wchar_t first[] = L"a/b";
      |    wchar_t second[] = L"a/b";
      |    wchar_t *slash = wcschr(first, L'/');
      |    if (slash == NULL) return 0;
      |    return (size_t)(slash - second);
      |}
      |int good_divide_zero_guarded(int total)
      |{
      |    int parts = 0;
      |    if (parts != 0) return total / parts;
      |    return 0;
      |}
      |double fabs(double);
      |double good_divide_magnitude_checked(void)
      |{
      |    char line[32];
      |    double scale;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0.0;
      |    scale = atof(line);
      |    if (fabs(scale) > 0.000001) return 100.0 / scale;
      |    return 0.0;
      |}
      |static const long digs[] = {1, 10, 100};
      |long good_divide_by_table(int total)
      |{
      |    char line[32];
      |    int len;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    len = atoi(line);
      |    if (len < 1 || len > 3) return 0;
      |    return ((long)total * 100) / digs[len - 1];
      |}
      |unsigned good_shift_by_remainder(void)
      |{
      |    char line[32];
      |    int chan;
      |    int off;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    chan = atoi(line);
      |    off = chan % 8;
      |    return 1u << off;
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
      |int bad_shift_negative_value(void)
      |{
      |    int value = -4;
      |    return value << 2;
      |}
      |int good_shift_positive_value(void)
      |{
      |    int value = 4;
      |    return value << 2;
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
      |double good_float_infinity(void)
      |{
      |    return 1.0 / 0;
      |}
      |int bad_float_zero_to_int(void)
      |{
      |    float scale = 0.0F;
      |    return (int)(100.0 / scale);
      |}
      |static const long scales[] = {1, 10, 100, 1000};
      |long good_divide_by_nonzero_table(int total)
      |{
      |    char line[32];
      |    int n;
      |    if (fgets(line, sizeof(line), stdin) == NULL) return 0;
      |    n = atoi(line);
      |    return total / scales[n & 3];
      |}
      |void good_copy_from_one_block_back(unsigned char *out, size_t len)
      |{
      |    size_t residue = len % 16;
      |    if (residue == 0) return;
      |    out += len - residue;
      |    memcpy(out, out - 16, residue);
      |}
      |void good_copy_to_unknown_offset(char *ctrl, size_t capacity)
      |{
      |    memcpy(ctrl + capacity + 1, ctrl, 15);
      |}
      |""".stripMargin,
    "undefined_operations.c"
  ).moreCode(
    """
      |struct span_of_time {
      |  long ticks;
      |  span_of_time &operator/=(long by);
      |};
      |span_of_time good_class_division(span_of_time lhs, long rhs) {
      |  return lhs /= rhs;
      |}
      |#include <cstdio>
      |#include <cstdlib>
      |template <typename T>
      |span_of_time good_dependent_class_division(span_of_time lhs, T rhs) {
      |  return lhs /= rhs;
      |}
      |span_of_time divide_by_input(span_of_time s) {
      |  char line[32];
      |  if (std::fgets(line, sizeof(line), stdin) == nullptr) return s;
      |  return good_dependent_class_division(s, std::atol(line));
      |}
      |""".stripMargin,
    "span_of_time.cpp"
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

  "a division" should {
      "report a divisor an untrusted read gives, or that is always zero" in {
          check(
            "MS-DIV-001",
            Seq(
              "bad_divide_input",
              "bad_modulo_input",
              "bad_float_divide",
              "bad_divide_by_literal_zero",
              "bad_divide_scanned",
              "bad_float_zero_to_int",
              "share"
            ),
            Seq(
              "good_divide_checked",
              "good_divide_zero_guarded",
              "good_divide_magnitude_checked",
              "good_divide_by_table",
              "good_divide_nonzero_guard",
              "good_divide_constant",
              "good_divide_clamped",
              "good_divide_short_circuit",
              "good_float_checked",
              "good_divide_parameter",
              "good_float_infinity",
              "good_divide_by_nonzero_table",
              "good_class_division",
              "good_dependent_class_division"
            )
          )
      }
  }

  "a shift" should {
      "report an amount outside [0, width), known or untrusted and unbounded" in {
          check(
            "MS-SHIFT-001",
            Seq(
              "bad_shift_by_input",
              "bad_shift_by_width",
              "bad_shift_negative_amount",
              "bad_shift_negative_value"
            ),
            Seq(
              "good_shift_masked",
              "good_shift_checked",
              "good_shift_wide",
              "good_shift_converted",
              "good_shift_by_remainder",
              "good_shift_positive_value",
              "good_shift_parameter"
            )
          )
      }
  }

  "a pointer subtraction" should {
      "report pointers into two different objects" in {
          check(
            "MS-PTR-001",
            Seq(
              "bad_index_in_other_string",
              "bad_distance_between_locals",
              "bad_wide_index_in_other_string"
            ),
            Seq("good_index_in_same_string", "good_end_minus_start", "good_parameters")
          )
      }
  }

  "a copy between disjoint objects" should {
      "report destination and source overlapping in one object" in {
          check(
            "MS-OVERLAP-001",
            Seq("bad_memcpy_overlap", "bad_memcpy_onto_itself_shifted", "bad_strcpy_overlap"),
            Seq(
              "good_memmove_overlap",
              "good_memcpy_disjoint",
              "good_memcpy_two_buffers",
              "good_copy_from_one_block_back",
              "good_copy_to_unknown_offset"
            )
          )
      }
  }
end UndefinedOperationRulesTests
