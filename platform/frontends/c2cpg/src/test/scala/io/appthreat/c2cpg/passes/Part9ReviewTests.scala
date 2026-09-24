package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 9 review, C: the shapes the int-handle narrowing and the self-sized copy get wrong. */
class Part9ReviewTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <fcntl.h>
    |#include <unistd.h>
    |
    |/* `-1` is a unary minus over a literal, not a literal */
    |int good_fd_eq_minus_one(const char *path)
    |{
    |    int fd = open(path, 1);
    |    if (fd == -1)
    |        return -1;
    |    close(fd);
    |    return 0;
    |}
    |
    |/* `fd >= 5` failing leaves descriptors 0..4 open: that side is not the failure side */
    |int bad_fd_ge_five(const char *path)
    |{
    |    int fd = open(path, 1);
    |    if (fd >= 5) {
    |        close(fd);
    |        return 0;
    |    }
    |    return -1;
    |}
    |
    |/* two fields of one struct are two buffers, not an in-place compaction */
    |struct two { char a[8]; char *b; };
    |void bad_sibling_fields(struct two *s, int len)
    |{
    |    memcpy(s->a, s->b, len);
    |}
    |
    |/* the length was changed after it sized the allocation */
    |int bad_len_grown_after_alloc(const unsigned char *s, int len)
    |{
    |    unsigned char *d = (unsigned char *)malloc(len);
    |    if (!d) return -1;
    |    len += 16;
    |    memcpy(d, s, len);
    |    free(d);
    |    return 0;
    |}
    |
    |/* udp.c: a header struct filled member by member through nested fields */
    |struct in_a { unsigned int s_addr; };
    |struct mreq_t { struct in_a imr_multiaddr; struct in_a imr_interface; };
    |int use_mreq(const void *p, int n);
    |int good_nested_member_writes(unsigned int a, int local)
    |{
    |    struct mreq_t mreq;
    |    mreq.imr_multiaddr.s_addr = a;
    |    if (local)
    |        mreq.imr_interface.s_addr = a;
    |    else
    |        mreq.imr_interface.s_addr = 0;
    |    return use_mreq(&mreq, (int)mreq.imr_interface.s_addr);
    |}
    |
    |/* a nested READ of a member nothing wrote is still one */
    |int bad_nested_member_read(void)
    |{
    |    struct mreq_t mreq;
    |    mreq.imr_multiaddr.s_addr = 1;
    |    return (int)mreq.imr_interface.s_addr;
    |}
    |""".stripMargin,
    "part9.c"
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

  "the int-handle failure check" should:
    "read `fd == -1` as the failure side" in {
        findingsIn("good_fd_eq_minus_one") should not contain "MS-ALLOC-003"
    }
    "not read a non-zero threshold as the failure side" in {
        findingsIn("bad_fd_ge_five") should contain("MS-ALLOC-003")
    }

  "MS-INIT-001" should:
    "count a nested member write as initialising the member" in {
        findingsIn("good_nested_member_writes") should not contain "MS-INIT-001"
    }
    "still report a nested read of an unwritten member" in {
        findingsIn("bad_nested_member_read") should contain("MS-INIT-001")
    }

  "the self-sized copy" should:
    "not treat sibling fields as an in-place compaction" in {
        findingsIn("bad_sibling_fields") should contain("MS-BOUND-002")
    }
    "not excuse a length redefined after the allocation" in {
        findingsIn("bad_len_grown_after_alloc") should contain("MS-BOUND-002")
    }
end Part9ReviewTests

/** Part 9 review, C++: the invalidation rule's re-take and reference-parameter arms. */
class Part9CppReviewTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <vector>
    |#include <string>
    |#include <iostream>
    |
    |/* erase and insert RETURN a valid iterator: assigning it is a re-take */
    |void good_erase_retake(std::vector<int> &v)
    |{
    |    auto it = v.begin();
    |    it = v.erase(it);
    |    std::cout << *it << "\n";
    |}
    |
    |/* a reference of another element type cannot point into this vector */
    |struct Item { int k; };
    |void good_ref_other_type(std::vector<int> &v, Item &item)
    |{
    |    v.push_back(1);
    |    item.k = 5;
    |}
    |""".stripMargin,
    "part9.cpp"
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

  "MS-INVAL-001" should:
    "treat `it = v.erase(it)` as a re-take" in {
        findingsIn("good_erase_retake") should not contain "MS-INVAL-001"
    }
    "not bind a reference parameter of another element type" in {
        findingsIn("good_ref_other_type") should not contain "MS-INVAL-001"
    }
end Part9CppReviewTests
