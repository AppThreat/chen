package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 10, task 3: the one-sided bounds check, the sign-converting check, the unbounded
  * container index, and the pointer-walk wraparound - with the negative shapes the task names.
  */
class Part10BoundsTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdint.h>
    |
    |struct fragment { int n; };
    |
    |int bad_upper_only(struct fragment *fragments, int count, int seq_no)
    |{
    |    if (seq_no < count)
    |    {
    |        return fragments[seq_no].n;
    |    }
    |    return -1;
    |}
    |
    |int bad_lower_only(struct fragment *fragments, int count, int seq_no)
    |{
    |    (void)count;
    |    if (seq_no >= 0)
    |    {
    |        return fragments[seq_no].n;
    |    }
    |    return -1;
    |}
    |
    |int bad_unsigned_compare_of_signed(struct fragment *fragments, unsigned count, int seq_no)
    |{
    |    if ((unsigned)seq_no < count)
    |    {
    |        return fragments[seq_no].n;
    |    }
    |    return -1;
    |}
    |
    |int good_both_bounds(struct fragment *fragments, int count, int seq_no)
    |{
    |    if (seq_no >= 0 && seq_no < count)
    |    {
    |        return fragments[seq_no].n;
    |    }
    |    return -1;
    |}
    |
    |int good_unsigned_upper(struct fragment *fragments, unsigned count, unsigned seq_no)
    |{
    |    if (seq_no < count)
    |    {
    |        return fragments[seq_no].n;
    |    }
    |    return -1;
    |}
    |
    |int good_rejection_does_not_return(struct fragment *fragments, int count, int seq_no)
    |{
    |    if (seq_no >= count)
    |    {
    |        log_out_of_range(seq_no);
    |    }
    |    return -1;
    |}
    |
    |void log_out_of_range(int v) { (void)v; }
    |
    |int bad_walk_wraparound(const unsigned char *buf, int rem_size)
    |{
    |    const unsigned char *p = buf;
    |    while (rem_size > 0)
    |    {
    |        uint32_t obu_size = (uint32_t)p[0] | ((uint32_t)p[1] << 24);
    |        p += obu_size;
    |        rem_size -= (int)obu_size;
    |    }
    |    return 0;
    |}
    |
    |int good_disjunctive_rejection(struct fragment *fragments, int count, int seq_no, int roll)
    |{
    |    if (seq_no > count || seq_no < 0 || roll)
    |    {
    |        return -1;
    |    }
    |    return fragments[seq_no].n;
    |}
    |
    |int good_walk_clamped(const unsigned char *buf, int size)
    |{
    |    const unsigned char *p = buf;
    |    const unsigned char *end = buf + size;
    |    while (end - p > 4)
    |    {
    |        uint32_t len = FFMIN(AV_RB32(p), end - p - 4);
    |        p += 4;
    |        p += len;
    |    }
    |    return 0;
    |}
    |
    |int good_walk_guarded(const unsigned char *buf, int rem_size)
    |{
    |    const unsigned char *p = buf;
    |    while (rem_size > 0)
    |    {
    |        uint32_t obu_size = (uint32_t)p[0] | ((uint32_t)p[1] << 24);
    |        if (obu_size > (uint32_t)rem_size) return -1;
    |        p += obu_size;
    |        rem_size -= (int)obu_size;
    |    }
    |    return 0;
    |}
    |""".stripMargin,
    "part10bounds.c"
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

  "debug" should:
    "print the cast comparison shape" in {
        List("bad_upper_only", "bad_lower_only", "bad_unsigned_compare_of_signed").foreach { mn =>
            cpg.method.nameExact(mn).ast.isCall
                .name("<operator>.indexAccess|<operator>.indirectIndexAccess").l
                .take(1)
                .foreach { access =>
                    val idx = access.argumentOption(2).head
                    val base = access.argumentOption(1).head
                    println(s"DBG2 $mn idx=${idx.code} tags=${idx.tag.l.map(t => t.name + "=" + t.value).mkString(",")} | base tags=${base.tag.l.map(t => t.name + "=" + t.value).mkString(",")}")
                }
            cpg.method.nameExact(mn).parameter.l.foreach(p =>
                println(s"DBG2 $mn param ${p.name}:${p.typeFullName} idx=${p.index}"))
        }
        cpg.method.nameExact("bad_unsigned_compare_of_signed").ast.isCall
            .name("<operator>.indexAccess|<operator>.indirectIndexAccess").l.foreach { access =>
                println(s"DBG idxaccess=<${access.code}> cdgIn=${access._cdgIn.l.map(n => s"${n.id}:${n.getClass.getSimpleName}:${n.property(io.shiftleft.codepropertygraph.generated.PropertyNames.CODE).toString.take(24)}").mkString(",")}")
                access._astIn.nextOption().foreach { p1 =>
                    println(s"DBG parent1=<${p1.getClass.getSimpleName}:${p1.property(io.shiftleft.codepropertygraph.generated.PropertyNames.CODE).toString.take(24)}> cdgIn=${p1._cdgIn.l.map(n => n.getClass.getSimpleName + ":" + n.property(io.shiftleft.codepropertygraph.generated.PropertyNames.CODE).toString.take(24)).mkString(",")}")
                }
                val idx = access.argumentOption(2).head
                println(s"DBG idx tags=${idx.tag.l.map(t => t.name + "=" + t.value).mkString(",")} type=<${idx.property(io.shiftleft.codepropertygraph.generated.PropertyNames.TYPE_FULL_NAME)}>")
                val base = access.argumentOption(1).head
                println(s"DBG base tags=${base.tag.l.map(t => t.name + "=" + t.value).mkString(",")}")
            }
    }

  "the one-sided bounds arm" should:
    "report an index bounded only above" in {
        findingsIn("bad_upper_only", "MS-BOUND-003") should not be empty
    }

    "report an index bounded only below" in {
        findingsIn("bad_lower_only", "MS-BOUND-003") should not be empty
    }

    "report a check that sees the index only through a sign-converting cast" in {
        findingsIn("bad_unsigned_compare_of_signed", "MS-BOUND-003") should not be empty
    }

    "stay silent on a two-sided check" in {
        findingsIn("good_both_bounds", "MS-BOUND-003") shouldBe empty
        findingsIn("good_both_bounds", "MS-BOUND-004") shouldBe empty
    }

    "stay silent on an unsigned index checked only above" in {
        findingsIn("good_unsigned_upper", "MS-BOUND-003") shouldBe empty
    }

    "stay silent when the check's rejection path does not return" in {
        findingsIn("good_rejection_does_not_return", "MS-BOUND-003") shouldBe empty
    }

    "split a rejecting disjunction whose third disjunct is not a comparison" in {
        findingsIn("good_disjunctive_rejection", "MS-BOUND-003") shouldBe empty
    }

  "the pointer-walk arm" should:
    "report an unguarded attacker-sized walk inside a loop" in {
        findingsIn("bad_walk_wraparound", "MS-BOUND-003") should not be empty
    }

    "stay silent when the step is bounded above" in {
        findingsIn("good_walk_guarded", "MS-BOUND-003") shouldBe empty
    }

    "stay silent when the step is clamped against the walked pointer" in {
        findingsIn("good_walk_clamped", "MS-BOUND-003") shouldBe empty
    }
end Part10BoundsTests

class Part10BoundsCppTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <vector>
    |#include <array>
    |#include <cstdlib>
    |#include <iostream>
    |
    |void bad_vector_index(const std::vector<int> &v, const char *userInput)
    |{
    |    std::size_t idx = static_cast<std::size_t>(std::atol(userInput));
    |    std::cout << v[idx] << "\n";
    |}
    |
    |void bad_array_write(std::array<int, 8> &a, int idx)
    |{
    |    a[idx] = 1;
    |}
    |
    |void good_at(const std::vector<int> &v, const char *userInput)
    |{
    |    std::size_t idx = static_cast<std::size_t>(std::atol(userInput));
    |    if (idx < v.size())
    |    {
    |        std::cout << v[idx] << "\n";
    |    }
    |}
    |""".stripMargin,
    "part10bounds.cpp"
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

  "the container arm" should:
    "report an unbounded attacker index into a std::vector" in {
        findingsIn("bad_vector_index", "MS-BOUND-003") should not be empty
    }

    "report an unbounded attacker index write into a std::array" in {
        findingsIn("bad_array_write", "MS-BOUND-004") should not be empty
    }

    "stay silent when the index is bounded above" in {
        findingsIn("good_at", "MS-BOUND-003") shouldBe empty
    }
end Part10BoundsCppTests
