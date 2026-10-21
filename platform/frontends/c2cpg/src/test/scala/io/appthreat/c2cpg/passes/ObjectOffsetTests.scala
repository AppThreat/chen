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

/** A pointer is an object and an offset, and an access has a size: the bytes before the object are
  * as much outside it as the bytes past its end; a view taken at an offset has what is left; an
  * element count converts to bytes through the element's size; a variable-length array's bound and
  * a flexible member's allocated room are capacities; and an access through a pointer converted to
  * a wider type reads past a narrower object.
  */
class ObjectOffsetTests extends DataFlowCodeToCpgSuite:

  private val sourceCpg = code(
    """
      |#include <stdio.h>
      |#include <stdlib.h>
      |#include <string.h>
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
      |int atoi(const char *);
      |void bad_offset_from_input(const char *user) {
      |    char buf[16];
      |    memset(buf, 0, sizeof(buf));
      |    size_t off = atoi(user);
      |    memcpy(buf + off, "tail", 4);
      |}
      |void good_offset_checked(const char *user) {
      |    char buf[16];
      |    size_t off = atoi(user);
      |    if (off > sizeof(buf) - 4) return;
      |    memcpy(buf + off, "tail", 4);
      |}
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
      |static void pair_sink(void *data) {
      |    print_pair((struct pair *)data);
      |}
      |void bad_struct_of_int_through_sink(void) {
      |    int value = 100;
      |    void *data = &value;
      |    pair_sink(data);
      |}
      |void good_struct_of_struct(void) {
      |    struct pair p = {1, 2};
      |    print_pair((struct pair *)&p);
      |}
      |struct digest_params { unsigned char salt[16]; };
      |void good_fill_remainder(struct digest_params *P, size_t len) {
      |    memset(P->salt + len, 0, 16 - len);
      |}
      |void good_fill_rest(unsigned char *okey, size_t okey_len, const unsigned char *digest,
      |    size_t cursize) {
      |    if (okey_len < cursize + 32)
      |        memcpy(okey + cursize, digest, okey_len - cursize);
      |}
      |#define PICK(to, from, m) ((to)[0] = ((m) >= 0) ? ((from)[m]) : 0)
      |unsigned good_constant_dead_branch(void) {
      |    unsigned words[8] = {0};
      |    unsigned out[1];
      |    PICK(out, words, (0) - 7);
      |    return out[0];
      |}
      |unsigned char good_unseen_size_constant(int qsize, const unsigned char *src) {
      |    unsigned char md[UNSEEN_MAX_SIZE];
      |    int i;
      |    for (i = 0; i < qsize; i++)
      |        md[i] = src[i];
      |    return md[0];
      |}
      |unsigned bad_constant_live_branch(void) {
      |    unsigned words[8] = {0};
      |    unsigned out[1];
      |    out[0] = words[(0) - 7];
      |    return out[0];
      |}
      |""".stripMargin,
    "object_offsets.c"
  ).moreCode(
    """
      |#include <cstring>
      |consteval unsigned long buffer_size() { return 16; }
      |void bad_consteval_sized_copy(const char *user) {
      |    char buf[buffer_size()];
      |    strcpy(buf, user);
      |}
      |""".stripMargin,
    "consteval_size.cpp"
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

  "the frontend's layout facts" should {
      "size a declared object in bytes" in {
          cpg.method.nameExact("bad_element_bytes").local.nameExact("counts").tag
              .nameExact("object-size").value.l shouldBe List("40")
      }
      "mark a variable-length array's bound" in {
          cpg.method.nameExact("bad_vla_copy").local.nameExact("buf").tag.nameExact("vla-size")
              .value.l shouldBe List("n")
      }
      "not mark an array whose constant bound the parser could not see" in {
          cpg.method.nameExact("good_unseen_size_constant").local.nameExact("md").tag
              .nameExact("vla-size").l shouldBe empty
      }
      "mark a flexible array member" in {
          cpg.member.nameExact("data").tag.nameExact("flexible-member").l should not be empty
      }
      "size a converted pointer's pointee" in {
          cpg.method.nameExact("bad_wider_read").call.nameExact("<operator>.cast").tag
              .nameExact("pointee-size").value.l should contain("4")
      }
  }

  "an access before the object" should {
      "report a write and a read at a known negative offset" in {
          findingsIn("bad_underwrite") should contain("MS-BOUND-009")
          findingsIn("bad_underread") should contain("MS-BOUND-010")
      }
      "stay silent where the offset leaves room" in {
          findingsIn("good_back_one").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }

  "the rest of a buffer from an offset" should {
      "end at the capacity, whatever the offset" in {
          findingsIn("good_fill_remainder").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
          findingsIn("good_fill_rest").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }

  "an access only a constant condition's other branch runs" should {
      "be on no path" in {
          findingsIn("good_constant_dead_branch") should not contain "MS-BOUND-010"
          findingsIn("bad_constant_live_branch") should contain("MS-BOUND-010")
      }
  }

  "a write through a view at an offset" should {
      "report what overruns the room left" in {
          findingsIn("bad_offset_overrun") should contain("MS-BOUND-006")
      }
      "stay silent where it fits" in {
          findingsIn("good_offset_fits").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }

  "a byte length into an int array" should {
      "compare bytes with bytes" in {
          findingsIn("bad_element_bytes") should contain("MS-BOUND-006")
          findingsIn("good_element_bytes").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }

  "an array sized by a constant function the parser did not fold" should {
      "have the function's constant as its capacity, not a run-time bound" in {
          findingsIn("bad_consteval_sized_copy") should contain("MS-BOUND-006")
          cpg.method.nameExact("bad_consteval_sized_copy").local.nameExact("buf").tag
              .nameExact("vla-size").l shouldBe empty
      }
  }

  "a variable-length array" should {
      "have its bound as its capacity" in {
          findingsIn("bad_vla_copy").exists(_.startsWith("MS-BOUND")) shouldBe true
          findingsIn("bad_vla_index") should contain("MS-BOUND-004")
          findingsIn("good_vla_copy").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }

  "a flexible array member" should {
      "have the room its allocation adds" in {
          findingsIn("bad_fam_copy").exists(_.startsWith("MS-BOUND")) shouldBe true
          findingsIn("bad_fam_alloc").exists(_.startsWith("MS-BOUND")) shouldBe true
          findingsIn("good_fam_copy").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }

  "a copy at an offset the input gives" should {
      "report the unbounded offset into a fixed buffer" in {
          findingsIn("bad_offset_from_input") should contain("MS-BOUND-006")
          findingsIn("good_offset_checked").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }

  "an access through a pointer converted to a wider type" should {
      "report the read past a narrower object" in {
          findingsIn("bad_wider_read") should contain("MS-BOUND-003")
          findingsIn("bad_struct_of_int") should contain("MS-BOUND-003")
          findingsIn("pair_sink") should contain("MS-BOUND-003")
      }
      "stay silent for an object as wide as the access" in {
          findingsIn("good_same_width").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
          findingsIn("good_struct_of_struct").filter(_.startsWith("MS-BOUND")) shouldBe Set.empty
      }
  }
end ObjectOffsetTests
