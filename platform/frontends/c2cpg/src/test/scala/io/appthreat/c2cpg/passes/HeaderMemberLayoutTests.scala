package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** A struct or class defined in a header is known to the graph only as an `<includes>` stub; the
  * member layout the AST pass records from CDT's bindings gives the stub its members, so a copy
  * into a header-declared member array (leveldb's `LookupKey::space_`) can be proven - also when
  * another translation unit names the class and a namesake in another namespace exists.
  */
class HeaderMemberLayoutTests extends DataFlowCodeToCpgSuite:
  private val cpg = code(
    """
    |#include <stdint.h>
    |#include <string.h>
    |#include "coding.h"
    |#include "dbformat.h"
    |namespace kv {
    |LookupKey::LookupKey(const Slice &user_key, uint64_t s)
    |{
    |    size_t usize = user_key.size();
    |    size_t needed = usize + 13;
    |    char *dst;
    |    if (needed <= sizeof(space_)) {
    |        dst = space_;
    |    } else {
    |        dst = new char[needed];
    |    }
    |    start_ = dst;
    |    dst = EncodeVarint32(dst, usize + 8);
    |    kstart_ = dst;
    |    memcpy(dst, user_key.data(), usize);
    |    dst += usize;
    |    end_ = dst;
    |}
    |}
    |""".stripMargin,
    "dbformat.cc"
  ).moreCode(
    """
    |#include <stdint.h>
    |namespace kv {
    |char *EncodeVarint32(char *dst, uint32_t value);
    |}
    |""".stripMargin,
    "coding.h"
  ).moreCode(
    """
    |#include <stddef.h>
    |#include <stdint.h>
    |namespace kv {
    |class Slice {
    |  public:
    |    Slice(const char *d, size_t n) : data_(d), size_(n) {}
    |    const char *data() const { return data_; }
    |    size_t size() const { return size_; }
    |  private:
    |    const char *data_;
    |    size_t size_;
    |};
    |class LookupKey {
    |  public:
    |    LookupKey(const Slice &user_key, uint64_t sequence);
    |    ~LookupKey();
    |    Slice memtable_key() const { return Slice(start_, end_ - start_); }
    |  private:
    |    const char *start_;
    |    const char *kstart_;
    |    const char *end_;
    |    char space_[200];
    |};
    |inline LookupKey::~LookupKey() {
    |  if (start_ != space_) delete[] start_;
    |}
    |}
    |""".stripMargin,
    "dbformat.h"
  ).moreCode(
    """
    |#include "coding.h"
    |namespace kv {
    |char *EncodeVarint32(char *dst, uint32_t v)
    |{
    |    uint8_t *ptr = reinterpret_cast<uint8_t *>(dst);
    |    static const int B = 128;
    |    if (v < (1 << 7)) {
    |        *(ptr++) = v;
    |    } else {
    |        *(ptr++) = v | B;
    |        *(ptr++) = v >> 7;
    |    }
    |    return reinterpret_cast<char *>(ptr);
    |}
    |}
    |""".stripMargin,
    "coding.cc"
  ).moreCode(
    """
    |#include "dbformat.h"
    |namespace other { class LookupKey; }
    |namespace kv {
    |size_t get(const LookupKey &key) { return key.memtable_key().size(); }
    |void forward(other::LookupKey *k) {}
    |}
    |""".stripMargin,
    "memtable.cc"
  ).moreCode(
    """
    |struct hdr { unsigned short len; char tag[16]; };
    |""".stripMargin,
    "hdr.inc"
  ).moreCode(
    """
    |#include "hdr.inc"
    |struct native { unsigned short len; char tag[16]; };
    |int tag_len(struct hdr *h) { return sizeof(h->tag) + h->len; }
    |int native_len(struct native *n) { return n->len; }
    |""".stripMargin,
    "use.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  "a header-defined class" should:
    "carry its ordered member layout on the stub type declaration" in {
        val members = cpg.typeDecl.fullNameExact("kv.LookupKey").member.l.sortBy(_.order)
        members.map(m => (m.name, m.typeFullName)) shouldBe List(
          ("start_", "char*"),
          ("kstart_", "char*"),
          ("end_", "char*"),
          ("space_", "char[200]")
        )
    }
    "be spelled with its full name by another translation unit that names it plainly" in {
        cpg.method.nameExact("get").parameter.typeFullName.l shouldBe List("kv.LookupKey")
        // the forward-declared namesake stays a member-less stub: the member lookup below must
        // go through the owner's full name, not whichever `LookupKey` comes first
        cpg.typeDecl.nameExact("LookupKey").fullName.l.sorted shouldBe List(
          "kv.LookupKey",
          "other.LookupKey"
        )
    }
    "let a guard on its member array prove the copy through an advancing helper" in {
        cpg.method.nameExact("LookupKey").ast.collectAll[StoredNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-BOUND-002")).l shouldBe empty
    }
    "record a C header struct's layout, spelled as a parsed struct's own members" in {
        val stub = cpg.typeDecl.fullNameExact("hdr").l
        stub.map(_.filename) shouldBe List("<includes>")
        stub.member.l.sortBy(_.order).map(m => (m.name, m.typeFullName)) shouldBe
            cpg.typeDecl.fullNameExact("native").member.l.sortBy(_.order).map(m =>
                (m.name, m.typeFullName)
            )
    }
end HeaderMemberLayoutTests
