package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ExtentPass, MemoryApiPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** D4: the member-extent search is whole-graph in both dimensions. An `init` allocates the member
  * and a `read_packet` writes it; the allocation may sit in a local first, or go through the
  * member's own address (`av_reallocp(&member, n)`). The writer's destination carries the extent
  * even though the allocation happened in another function.
  */
class ExtentPassMemberSearchTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <string.h>
    |#include <stdlib.h>
    |
    |struct one { unsigned char *buf; };
    |struct local_holder { unsigned char *buf; };
    |struct viaaddr { unsigned char *buf; };
    |struct cross { unsigned char *buf; };
    |
    |int my_reallocp(void *ptr, size_t size);
    |
    |/* the allocation reaches the member through a local, in the same body */
    |void member_via_local(unsigned char *src, int n) {
    |    struct local_holder w;
    |    unsigned char *tmp = malloc(96);
    |    w.buf = tmp;
    |    memcpy(w.buf, src, n);
    |}
    |
    |/* the allocation happens THROUGH the member's own address, in another function */
    |void grow_via_address(struct viaaddr *w) {
    |    my_reallocp(&w->buf, 128);
    |}
    |
    |void write_via_address(struct viaaddr *w, unsigned char *src, int n) {
    |    memcpy(w->buf, src, n);
    |}
    |
    |/* allocated in one function, written in another - the plain C1 shape across functions.
    | * (struct `cross` is this member's ONLY allocator: two sites would carry two `alloc:` node
    | * ids, which is the no-single-capacity conflict, not this shape.) */
    |void init_elsewhere(struct cross *w) {
    |    w->buf = malloc(256);
    |}
    |
    |void write_elsewhere(struct cross *w, unsigned char *src, int n) {
    |    memcpy(w->buf, src, n);
    |}
    |""".stripMargin,
    "member_search.c"
  )

  new MemoryApiPass(
    cpg,
    Some("""{"version": 1, "apis": [{"name": "my_reallocp", "len": 2, "realloc": "heap"}]}""")
  ).createAndApply()
  new ExtentPass(cpg).createAndApply()

  private def dstExtentOf(methodName: String): List[String] =
      cpg.method
          .name(methodName)
          .call
          .name("memcpy")
          .l
          .flatMap(_.argument.l)
          .flatMap(_.tag.name("extent").value.l)

  "ExtentPass member search (D4)" should:

    "type a member written through a local that holds the allocation" in {
        dstExtentOf("member_via_local").headOption.map(_.startsWith("alloc:")) shouldBe Some(true)
    }

    "type a member allocated through its own address in another function" in {
        val extent = dstExtentOf("write_via_address").head
        extent.startsWith("alloc:") shouldBe true
        val sizeNodeId = extent.stripPrefix("alloc:").toLong
        cpg.literal.code("128").l.map(_.id) should contain(sizeNodeId)
    }

    "type a member allocated in one function and written in another" in {
        val extent = dstExtentOf("write_elsewhere").head
        extent.startsWith("alloc:") shouldBe true
        val sizeNodeId = extent.stripPrefix("alloc:").toLong
        cpg.literal.code("256").l.map(_.id) should contain(sizeNodeId)
    }
end ExtentPassMemberSearchTests
