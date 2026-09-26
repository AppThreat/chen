package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Part 12: the generalisation round. One class per FP cause measured on leveldb and abseil; every
  * cause ships a negative control (the FP shape, reduced to its skeleton - must be silent) and a
  * positive twin (the real bug the silence must not swallow - must still fire).
  */
class Part12LeakTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |struct writer
    |{
    |    int fd;
    |    explicit writer(int f) : fd(f) {}
    |};
    |
    |/* the fd is handed to the constructed object, which owns it from here - the exit is
    |   not a leak (part 12 cause 1: ownership through a constructed object) */
    |int make_writer(writer **result)
    |{
    |    int fd = open("log.txt", 1);
    |    if (fd < 0)
    |        return -1;
    |    *result = new writer(fd);
    |    return 0;
    |}
    |
    |/* positive twin: the fd is never handed anywhere - a real leak */
    |int make_writer_leaky(writer **result)
    |{
    |    int fd = open("log.txt", 1);
    |    if (fd < 0)
    |        return -1;
    |    return 0;
    |}
    |
    |/* positive twin: the object itself is allocated into a local and dropped - a real leak
    |   that must not be excused by the constructor's own argument hand-off */
    |int make_writer_dropped(writer **result)
    |{
    |    int fd = open("log.txt", 1);
    |    if (fd < 0)
    |        return -1;
    |    writer *w = new writer(fd);
    |    (void)w;
    |    return 0;
    |}
    |""".stripMargin,
    "part12leak.cpp"
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

  "stay silent when the tracked fd is handed to a constructed object" in {
      findingsIn("make_writer", "MS-ALLOC-003") shouldBe empty
  }

  "still fire when the fd is never handed anywhere" in {
      findingsIn("make_writer_leaky", "MS-ALLOC-003") should not be empty
  }

  "still fire when the allocated object itself is dropped" in {
      findingsIn("make_writer_dropped", "MS-ALLOC-003") should not be empty
  }

end Part12LeakTests

class Part12EscapeTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <string>
    |
    |char *g_alias;
    |
    |/* a std::string target copies the characters - no frame address is stored
    |   (part 12 cause 5: std::string owns its buffer) */
    |void fill(std::string *value)
    |{
    |    char buf[16];
    |    buf[0] = 'o';
    |    buf[1] = 0;
    |    *value = buf;
    |}
    |
    |/* a std::string return copies out of the frame - the address never escapes */
    |std::string describe()
    |{
    |    char buf[16];
    |    buf[0] = 'd';
    |    buf[1] = 0;
    |    const char *s = buf;
    |    return s;
    |}
    |
    |/* positive twin: a char* target really does store the frame address */
    |void take_alias(char **out)
    |{
    |    char buf[16];
    |    buf[0] = 'x';
    |    buf[1] = 0;
    |    *out = buf;
    |}
    |
    |/* positive twin: a char* return really does let the frame address escape */
    |const char *view()
    |{
    |    char buf[16];
    |    buf[0] = 'y';
    |    buf[1] = 0;
    |    return buf;
    |}
    |""".stripMargin,
    "part12escape.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def lineOf(n: StoredNode): Int =
      n.property("LINE_NUMBER") match
        case i: Integer => i
        case _          => -1

  private def escapeSites(method: String): List[(String, Int)] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains("MS-ESC-001"))
          .map(n => ("MS-ESC-001", lineOf(n))).l

  "stay silent when the stack buffer is copied into a std::string target" in {
      escapeSites("fill") shouldBe empty
  }

  "stay silent when the stack buffer is copied out through a std::string return" in {
      escapeSites("describe") shouldBe empty
  }

  "still fire when a char* target stores the frame address" in {
      escapeSites("take_alias") should not be empty
  }

  "still fire when a char* return lets the frame address escape" in {
      escapeSites("view") should not be empty
  }

end Part12EscapeTests

class Part12NullGuardTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |struct node
    |{
    |    struct node *next;
    |    int marked;
    |};
    |
    |/* the conjunction loop condition narrows the body's use of n; the later bare check
    |   guards its own statement, it is not a check-after-use (part 12 cause 4) */
    |int drain(struct node *head)
    |{
    |    struct node *n = head;
    |    int walked = 0;
    |    while (n && !n->marked)
    |    {
    |        walked++;
    |        n = n->next;
    |    }
    |    if (n)
    |    {
    |        walked += 2;
    |    }
    |    return walked;
    |}
    |
    |/* the ternary's own condition narrows the else arm; the later guard belongs to a
    |   different statement */
    |int pick(struct node *n)
    |{
    |    int v = n == 0 ? 0 : n->marked;
    |    if (n == 0)
    |    {
    |        v += 1;
    |    }
    |    return v;
    |}
    |
    |/* positive twin: the use precedes its only guard - a real check-after-use */
    |int late_check(struct node *n)
    |{
    |    int v = n->marked;
    |    if (n == 0)
    |    {
    |        return 0;
    |    }
    |    return v;
    |}
    |
    |/* positive twin: the deref sits on the NULL side of its own ternary */
    |int bad_ternary(struct node *n)
    |{
    |    int v = n == 0 ? n->marked : 0;
    |    if (n == 0)
    |    {
    |        return 0;
    |    }
    |    return v;
    |}
    |""".stripMargin,
    "part12null.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def lineOf(n: StoredNode): Int =
      n.property("LINE_NUMBER") match
        case i: Integer => i
        case _          => -1

  private def findingsIn(method: String): Set[(String, Int)] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains("MS-NULL-001"))
          .map(n => ("MS-NULL-001", lineOf(n))).l.toSet

  "stay silent when a conjunction loop condition narrows the body's use" in {
      findingsIn("drain") shouldBe empty
  }

  "stay silent when the use sits in the ternary arm its condition narrows" in {
      findingsIn("pick") shouldBe empty
  }

  "still fire when the only guard comes after the use" in {
      findingsIn("late_check") should not be empty
  }

  "still fire when the deref sits on the null side of its own ternary" in {
      findingsIn("bad_ternary") should not be empty
  }

end Part12NullGuardTests

class Part12BoundsTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |struct key
    |{
    |    char space_[24];
    |};
    |
    |struct entry
    |{
    |    int refs;
    |    char data[1];
    |};
    |
    |struct pair
    |{
    |    char tag[4];
    |    char data[1];
    |};
    |
    |/* the destination is sized from the same length in both branches: the fixed member
    |   when it fits, a new[] of the exact need otherwise (part 12 cause 2) */
    |void store(struct key *k, const char *bytes, unsigned n)
    |{
    |    size_t need = n + 8;
    |    char *dst;
    |    if (need <= sizeof(k->space_))
    |        dst = k->space_;
    |    else
    |        dst = new char[need];
    |    memcpy(dst, bytes, n);
    |}
    |
    |/* a sized malloc with a flexible trailing member, copied with the same length */
    |void put(struct entry **slot, const char *bytes, unsigned n)
    |{
    |    struct entry *e = (struct entry *)malloc(sizeof(struct entry) - 1 + n);
    |    e->refs = 1;
    |    memcpy(e->data, bytes, n);
    |    *slot = e;
    |}
    |
    |/* positive twin: the allocation is sized without the copy's length - a real overrun */
    |void over(struct entry **slot, const char *bytes, unsigned n)
    |{
    |    struct entry *e = (struct entry *)malloc(sizeof(struct entry) + 4);
    |    e->refs = 1;
    |    memcpy(e->data, bytes, n);
    |    *slot = e;
    |}
    |
    |/* positive twin: the length was in the malloc, but the copy goes into the fixed
    |   4-byte member, not the flexible one - a real intra-object overrun */
    |void wrong_member(struct pair **slot, const char *bytes, unsigned n)
    |{
    |    struct pair *p = (struct pair *)malloc(sizeof(struct pair) - 1 + n);
    |    p->refs = 1;
    |    memcpy(p->tag, bytes, n);
    |    *slot = p;
    |}
    |""".stripMargin,
    "part12bounds.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def lineOf(n: StoredNode): Int =
      n.property("LINE_NUMBER") match
        case i: Integer => i
        case _          => -1

  private def findingsIn(method: String): Set[(String, Int)] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains("MS-BOUND-002"))
          .map(n => ("MS-BOUND-002", lineOf(n))).l.toSet

  "stay silent when both branches size the destination from the copy's length" in {
      findingsIn("store") shouldBe empty
  }

  "stay silent when a sized malloc's flexible trailing member takes the copy" in {
      findingsIn("put") shouldBe empty
  }

  "still fire when the allocation is sized without the copy's length" in {
      findingsIn("over") should not be empty
  }

  "still fire when the copy lands in a fixed member of a sized allocation" in {
      findingsIn("wrong_member") should not be empty
  }

end Part12BoundsTests

class Part12MinClampTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <algorithm>
    |#include <string.h>
    |
    |class slice
    |{
    |  public:
    |    size_t size() const { return len_; }
    |    const char *data() const { return p_; }
    |  private:
    |    const char *p_;
    |    size_t len_;
    |};
    |
    |constexpr const size_t kBigSize = 65536;
    |
    |/* the copy length is clamped to the buffer's remaining capacity: the min's arm is
    |   the buffer's own extent minus the position written to (part 12 cause 3) */
    |class wfile
    |{
    |  public:
    |    void append(const slice &data)
    |    {
    |        size_t write_size = data.size();
    |        const char *write_data = data.data();
    |        size_t copy_size = std::min(write_size, kBigSize - pos_);
    |        std::memcpy(buf_ + pos_, write_data, copy_size);
    |        pos_ += copy_size;
    |    }
    |
    |    /* positive twin: the clamp is against a constant larger than the buffer the
    |       copy writes into - a real overrun the min does not prevent */
    |    void over_append(const slice &data)
    |    {
    |        size_t write_size = data.size();
    |        const char *write_data = data.data();
    |        size_t copy_size = std::min(write_size, kBigSize - pos_);
    |        std::memcpy(small_ + pos_, write_data, copy_size);
    |        pos_ += copy_size;
    |    }
    |
    |  private:
    |    char buf_[kBigSize];
    |    char small_[512];
    |    size_t pos_;
    |};
    |""".stripMargin,
    "part12min.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def lineOf(n: StoredNode): Int =
      n.property("LINE_NUMBER") match
        case i: Integer => i
        case _          => -1

  private def findingsIn(method: String): Set[(String, Int)] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains("MS-BOUND-002"))
          .map(n => ("MS-BOUND-002", lineOf(n))).l.toSet

  "stay silent when the length is clamped to the destination's remaining capacity" in {
      findingsIn("append") shouldBe empty
  }

  "still fire when the clamp constant exceeds the destination's capacity" in {
      findingsIn("over_append") should not be empty
  }

end Part12MinClampTests
