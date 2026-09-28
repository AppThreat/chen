package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A destination pointer moved by constants - directly, or through a helper that returns its
  * argument advanced by a bounded amount - is self-sized when the size holds the length plus that
  * advance; a `c ? a : b` destination is proven arm by arm.
  */
class AdvancedDestinationTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdint.h>
    |#include <stdlib.h>
    |#include <string.h>
    |
    |struct Slice {
    |    const char *data_;
    |    size_t size_;
    |    const char *data() const { return data_; }
    |    size_t size() const { return size_; }
    |};
    |struct LookupKey { char space_[200]; const char *start_; };
    |
    |namespace kv {
    |char *EncodeVarint32(char *dst, uint32_t v);
    |class LookupKey2 {
    |  public:
    |    LookupKey2(const Slice &user_key, uint64_t s);
    |  private:
    |    const char *start_;
    |    const char *kstart_;
    |    const char *end_;
    |    char space_[200];
    |};
    |LookupKey2::LookupKey2(const Slice &user_key, uint64_t s)
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
    |char *EncodeVarint32(char *dst, uint32_t v)
    |{
    |    uint8_t *ptr = reinterpret_cast<uint8_t *>(dst);
    |    if (v < (1 << 7)) {
    |        *(ptr++) = v;
    |    } else {
    |        *(ptr++) = v | 128;
    |        *(ptr++) = v >> 7;
    |    }
    |    return reinterpret_cast<char *>(ptr);
    |}
    |}
    |
    |/* returns dst advanced by 1 to 5 bytes */
    |char *EncodeVarint32(char *dst, uint32_t v)
    |{
    |    uint8_t *ptr = reinterpret_cast<uint8_t *>(dst);
    |    static const int B = 128;
    |    if (v < (1 << 7)) {
    |        *(ptr++) = v;
    |    } else if (v < (1 << 14)) {
    |        *(ptr++) = v | B;
    |        *(ptr++) = v >> 7;
    |    } else if (v < (1 << 21)) {
    |        *(ptr++) = v | B;
    |        *(ptr++) = (v >> 7) | B;
    |        *(ptr++) = v >> 14;
    |    } else if (v < (1 << 28)) {
    |        *(ptr++) = v | B;
    |        *(ptr++) = (v >> 7) | B;
    |        *(ptr++) = (v >> 14) | B;
    |        *(ptr++) = v >> 21;
    |    } else {
    |        *(ptr++) = v | B;
    |        *(ptr++) = (v >> 7) | B;
    |        *(ptr++) = (v >> 14) | B;
    |        *(ptr++) = (v >> 21) | B;
    |        *(ptr++) = v >> 28;
    |    }
    |    return reinterpret_cast<char *>(ptr);
    |}
    |
    |/* returns dst advanced by 16 bytes */
    |char *EncodeWide(char *dst, uint32_t v)
    |{
    |    memset(dst, 0, 16);
    |    return dst + 16;
    |}
    |
    |/* returns dst advanced by as many bytes as v has groups: no bound */
    |char *EncodeLoop(char *dst, uint64_t v)
    |{
    |    uint8_t *ptr = reinterpret_cast<uint8_t *>(dst);
    |    while (v >= 128) {
    |        *(ptr++) = v | 128;
    |        v >>= 7;
    |    }
    |    *(ptr++) = v;
    |    return reinterpret_cast<char *>(ptr);
    |}
    |
    |void lookup_key(LookupKey *k, const Slice &user_key)
    |{
    |    size_t usize = user_key.size();
    |    size_t needed = usize + 13;
    |    char *dst;
    |    if (needed <= sizeof(k->space_))
    |        dst = k->space_;
    |    else
    |        dst = new char[needed];
    |    k->start_ = dst;
    |    dst = EncodeVarint32(dst, usize + 8);
    |    memcpy(dst, user_key.data(), usize);
    |}
    |
    |/* the header needs 16 bytes, the size leaves 13 */
    |void lookup_key_wide_header(LookupKey *k, const Slice &user_key)
    |{
    |    size_t usize = user_key.size();
    |    size_t needed = usize + 13;
    |    char *dst;
    |    if (needed <= sizeof(k->space_))
    |        dst = k->space_;
    |    else
    |        dst = new char[needed];
    |    dst = EncodeWide(dst, usize + 8);
    |    memcpy(dst, user_key.data(), usize);
    |}
    |
    |void lookup_key_unbounded_header(LookupKey *k, const Slice &user_key)
    |{
    |    size_t usize = user_key.size();
    |    size_t needed = usize + 13;
    |    char *dst;
    |    if (needed <= sizeof(k->space_))
    |        dst = k->space_;
    |    else
    |        dst = new char[needed];
    |    dst = EncodeLoop(dst, usize + 8);
    |    memcpy(dst, user_key.data(), usize);
    |}
    |
    |void advanced_within_the_size(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)malloc((size_t)n + 4);
    |    d += 4;
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |void advanced_by_an_addition(const char *s, unsigned n, char **out)
    |{
    |    char *p = (char *)malloc((size_t)n + 4);
    |    char *d = p + 4;
    |    memcpy(d, s, n);
    |    *out = p;
    |}
    |
    |void advanced_past_the_size(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)malloc((size_t)n + 2);
    |    d += 4;
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |void advanced_in_a_loop(const char *s, unsigned n, int k, char **out)
    |{
    |    char *d = (char *)malloc((size_t)n + 4);
    |    for (int i = 0; i < k; i++)
    |        d++;
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |void ternary_destination(const char *s, unsigned n, char **out)
    |{
    |    char buf[64];
    |    char *dst = n <= sizeof(buf) ? buf : new char[n];
    |    memcpy(dst, s, n);
    |    *out = dst;
    |}
    |
    |void ternary_wrong_way(const char *s, unsigned n, char **out)
    |{
    |    char buf[64];
    |    char *dst = n >= sizeof(buf) ? buf : new char[n];
    |    memcpy(dst, s, n);
    |    *out = dst;
    |}
    |""".stripMargin,
    "advanced_destination.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): List[StoredNode] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .filter(n => n.tag.name("ms-finding").value.l.contains("MS-BOUND-002")).l

  private val mustFire = List(
    "lookup_key_wide_header",
    "lookup_key_unbounded_header",
    "advanced_past_the_size",
    "advanced_in_a_loop",
    "ternary_wrong_way"
  )
  private val mustStaySilent = List(
    "lookup_key",
    "LookupKey2",
    "advanced_within_the_size",
    "advanced_by_an_addition",
    "ternary_destination"
  )

  "an advanced or conditional destination" should:
    mustFire.foreach(m => s"report $m" in { findingsIn(m) should not be empty })
    mustStaySilent.foreach(m => s"stay silent on $m" in { findingsIn(m) shouldBe empty })
end AdvancedDestinationTests
