package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** MS-INVAL-001 (CWE-416): a view into a std container - iterator, reference or pointer - used
  * after a call that may reallocate or restructure the same container, with no re-take in
  * between.
 */
class ContainerInvalidationRulesTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <vector>
    |#include <string>
    |#include <iostream>
    |
    |void bad_iterator_invalidation(std::vector<int> &v)
    |{
    |    auto it = v.begin();
    |    v.push_back(42);
    |    std::cout << *it << "\n";
    |}
    |
    |void bad_reference_invalidation(std::vector<int> &v)
    |{
    |    int &first = v[0];
    |    v.resize(v.size() * 2);
    |    first = 7;
    |}
    |
    |void bad_erase_then_use(std::vector<int> &v)
    |{
    |    for (auto it = v.begin(); it != v.end(); ++it)
    |    {
    |        if (*it == 3)
    |        {
    |            v.erase(it);
    |            std::cout << *it << "\n";
    |        }
    |    }
    |}
    |
    |void bad_pointer_invalidation(std::vector<int> &v)
    |{
    |    int *p = &v[0];
    |    v.emplace_back(7);
    |    p[0] = 1;
    |}
    |
    |void bad_string_cstr(std::string &s)
    |{
    |    const char *c = s.c_str();
    |    s.append("x");
    |    std::cout << c << "\n";
    |}
    |
    |void bad_dangling_reference_param(std::vector<int> &v, int &elem)
    |{
    |    v.push_back(1);
    |    elem = 5;
    |}
    |
    |void good_retaken(std::vector<int> &v)
    |{
    |    auto it = v.begin();
    |    v.push_back(42);
    |    it = v.begin();
    |    std::cout << *it << "\n";
    |}
    |
    |void good_reserved(std::vector<int> &v)
    |{
    |    v.reserve(1000);
    |    int &first = v[0];
    |    v.push_back(9);
    |    first = 7;
    |}
    |
    |void good_other_container(std::vector<int> &v, std::vector<int> &w)
    |{
    |    int &first = v[0];
    |    w.push_back(9);
    |    first = 7;
    |}
    |
    |void good_use_before(std::vector<int> &v)
    |{
    |    int &first = v[0];
    |    first = 7;
    |    v.push_back(9);
    |}
    |""".stripMargin,
    "invalidation.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  private def lowConfidenceIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-confidence").value.l).l.toSet

  "MS-INVAL-001" should:
    "report a view used after the container may have reallocated it" in {
        Seq(
          "bad_iterator_invalidation",
          "bad_reference_invalidation",
          "bad_erase_then_use",
          "bad_pointer_invalidation",
          "bad_string_cstr",
          "bad_dangling_reference_param"
        ).foreach { m => withClue(m) { findingsIn(m) should contain("MS-INVAL-001") } }
    }
    "anchor the report at the use, on the view's identifier" in {
        val uses = cpg.method.nameExact("bad_reference_invalidation").ast.collectAll[StoredNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-INVAL-001")).l
        uses.size shouldBe 1
        uses.head.propertyOption("CODE").get.toString should include("first")
    }
    "carry the may-alias hypothesis tier on the reference-parameter arm" in {
        // a caller may have bound `elem` to this vector's storage or to something else
        // entirely - the arm cannot tell, and says so at low confidence
        lowConfidenceIn("bad_dangling_reference_param") should contain("MS-INVAL-001=low")
        lowConfidenceIn("bad_reference_invalidation") shouldBe empty
    }
    "leave a re-taken view, a reserve-protected growth, another container and earlier uses alone" in {
        Seq("good_retaken", "good_reserved", "good_other_container", "good_use_before").foreach { m =>
            withClue(m) { findingsIn(m) should not contain "MS-INVAL-001" }
        }
    }
