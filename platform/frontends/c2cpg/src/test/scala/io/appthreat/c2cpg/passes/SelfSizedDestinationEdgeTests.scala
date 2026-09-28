package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A self-sized destination must be proven on every value, by the very local, at the very offset,
  * with a length that cannot wrap or change - and the other self-sized arms must not excuse what
  * their idiom does not cover.
  */
class SelfSizedDestinationEdgeTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |void shift(char **pp);
    |void get_len(unsigned *n);
    |void note(void);
    |struct key { char space_[24]; };
    |struct entry { int refs; char data[1]; };
    |struct msg { unsigned len; };
    |typedef struct AVPacket { unsigned char *data; int size; } AVPacket;
    |int av_new_packet(AVPacket *pkt, int size);
    |int av_grow_packet(AVPacket *pkt, int grow_by);
    |static const unsigned char start_sequence[] = { 0, 0, 0, 1 };
    |
    |void advanced_by_compound(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)malloc(n);
    |    d += 10;
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |void advanced_by_increment(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)malloc(n);
    |    d++;
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |void replaced_through_address(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)malloc(n);
    |    shift(&d);
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |void sizeof_of_a_pointer(char *p, const char *bytes, unsigned n)
    |{
    |    size_t need = (size_t)n + 8;
    |    char *dst;
    |    if (need <= sizeof(p))
    |        dst = p;
    |    else
    |        dst = new char[need];
    |    memcpy(dst, bytes, n);
    |}
    |
    |void sizeof_of_an_array_parameter(char buf[64], const char *bytes, unsigned n)
    |{
    |    size_t need = (size_t)n + 8;
    |    char *dst;
    |    if (need <= sizeof(buf))
    |        dst = buf;
    |    else
    |        dst = new char[need];
    |    memcpy(dst, bytes, n);
    |}
    |
    |/* n + 8 is computed in unsigned int: n = 0xFFFFFFF8 makes need 0 */
    |void guard_sum_wraps(struct key *k, const char *bytes, unsigned n)
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
    |/* the else exits, so the condition holds after the if - the assignment is not inside it */
    |void guard_else_exits(struct key *k, const char *bytes, unsigned n)
    |{
    |    size_t need = (size_t)n + 8;
    |    char *dst;
    |    if (need > sizeof(k->space_)) {
    |        note();
    |    } else {
    |        return;
    |    }
    |    dst = k->space_;
    |    memcpy(dst, bytes, n);
    |}
    |
    |/* the correct twin: an early exit leaves the condition false after the if */
    |void guard_by_early_exit(struct key *k, const char *bytes, unsigned n)
    |{
    |    size_t need = (size_t)n + 8;
    |    char *dst;
    |    if (need > sizeof(k->space_))
    |        return;
    |    dst = k->space_;
    |    memcpy(dst, bytes, n);
    |}
    |
    |void length_changed_through_address(struct key *k, const char *bytes, unsigned n)
    |{
    |    size_t need = (size_t)n + 8;
    |    char *dst;
    |    if (need <= sizeof(k->space_))
    |        dst = k->space_;
    |    else
    |        dst = new char[need];
    |    get_len(&n);
    |    memcpy(dst, bytes, n);
    |}
    |
    |static char *cache;
    |static int ready;
    |/* a later call with a larger n reuses the first allocation */
    |void global_keeps_its_value(const char *s, unsigned n)
    |{
    |    if (!ready) {
    |        cache = (char *)malloc(n);
    |        ready = 1;
    |    }
    |    memcpy(cache, s, n);
    |}
    |
    |void static_local_keeps_its_value(const char *s, unsigned n)
    |{
    |    static char *keep;
    |    if (!keep)
    |        keep = (char *)malloc(n);
    |    memcpy(keep, s, n);
    |}
    |
    |/* the inner d is another variable */
    |void shadowed(const char *s, unsigned n, char **out)
    |{
    |    char buf[16];
    |    char *d = buf;
    |    {
    |        char *d = (char *)malloc(n);
    |        *out = d;
    |    }
    |    memcpy(d, s, n);
    |}
    |
    |void copy_at_an_offset(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)malloc(n);
    |    memcpy(d + 1, s, n);
    |    *out = d;
    |}
    |
    |/* the correct twin: the offset is an addend of the size */
    |void copy_after_a_header(const char *s, unsigned n, unsigned hdr, char **out)
    |{
    |    char *d = (char *)malloc(hdr + n);
    |    memcpy(d + hdr, s, n);
    |    *out = d;
    |}
    |
    |void size_local_with_two_values(const char *s, unsigned n, int c, char **out)
    |{
    |    unsigned total = n;
    |    if (c)
    |        total = 4;
    |    char *d = (char *)malloc(total);
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |/* strndup allocates min(strlen(t), n) + 1 */
    |void copying_allocator(const char *t, const char *s, unsigned n, char **out)
    |{
    |    char *d = strndup(t, n);
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |void calloc_with_a_variable_count(const char *s, unsigned n, unsigned k, char **out)
    |{
    |    char *d = (char *)calloc(k, n);
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |/* the correct twin: calloc(1, n) is n bytes */
    |void calloc_of_one(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)calloc(1, n);
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |/* strncat appends n bytes after what d already holds */
    |void appending_copy(const char *s, unsigned n, char **out)
    |{
    |    char *d = (char *)malloc(n);
    |    d[0] = 0;
    |    strncat(d, "x", 1);
    |    strncat(d, s, n);
    |    *out = d;
    |}
    |
    |void in_place_without_the_offset(const char *s, unsigned n)
    |{
    |    char buf[16];
    |    memcpy(buf, s, 16);
    |    memmove(buf, buf + 1, n);
    |}
    |
    |/* the correct twin: the documented strip */
    |void in_place_strip(char *buf, unsigned len, unsigned k)
    |{
    |    memmove(buf, buf + k, len - k);
    |}
    |
    |/* the correct twin: a use in the loop body does not change the pointer */
    |void reused_in_a_loop(const char **s, unsigned n, int count, char **out)
    |{
    |    char *d = (char *)malloc(n);
    |    for (int i = 0; i < count; i++) {
    |        memcpy(d, s[i], n);
    |        d[n - 1] = 0;
    |    }
    |    *out = d;
    |}
    |
    |/* the correct twin: the header is read through its address, then the body copied after it */
    |void header_then_body(const char *s, unsigned n, char **out)
    |{
    |    const unsigned size = n;
    |    char *d = new char[size + 5];
    |    memcpy(d, &size, sizeof(size));
    |    memcpy(d + 5, s, n);
    |    *out = d;
    |}
    |
    |void packet_after_header(AVPacket *pkt, const unsigned char *buf, int len)
    |{
    |    if (av_new_packet(pkt, len + sizeof(start_sequence)) < 0)
    |        return;
    |    memcpy(pkt->data, start_sequence, sizeof(start_sequence));
    |    memcpy(pkt->data + sizeof(start_sequence), buf, len);
    |}
    |
    |void packet_grow_append(AVPacket *pkt, const unsigned char *buf, int len)
    |{
    |    int old_len = pkt->size;
    |    if (av_grow_packet(pkt, len) < 0)
    |        return;
    |    memcpy(pkt->data + old_len, buf, len);
    |}
    |
    |void packet_grow_wrong_offset(AVPacket *pkt, const unsigned char *buf, int len)
    |{
    |    if (av_grow_packet(pkt, len) < 0)
    |        return;
    |    memcpy(pkt->data + 4, buf, len);
    |}
    |
    |void in_place_compound(char *buf, unsigned *len, unsigned k)
    |{
    |    *len -= k;
    |    memmove(buf, buf + k, *len);
    |}
    |
    |void offset_is_a_constant_local(const char *s, unsigned n, char **out)
    |{
    |    const int sz = 4;
    |    char *d = (char *)malloc(n + sz);
    |    memcpy(d + sz, s, n);
    |    *out = d;
    |}
    |
    |void length_is_a_single_valued_local(const char *s, unsigned n, unsigned h, char **out)
    |{
    |    unsigned isize = n;
    |    unsigned total = isize + h;
    |    char *d = (char *)malloc(total + 64);
    |    memcpy(d, s, h);
    |    memcpy(d + h, s, isize);
    |    *out = d;
    |}
    |
    |/* allocated on the first iteration only; every later one copies a new length into it */
    |void reuse_first_allocation(const char *s, const unsigned *lens, int count, char **out)
    |{
    |    char *d;
    |    int first = 1;
    |    for (int i = 0; i < count; i++) {
    |        unsigned n = *lens;
    |        lens++;
    |        if (first) {
    |            d = (char *)malloc(n);
    |            first = 0;
    |        }
    |        memcpy(d, s, n);
    |        *out = d;
    |    }
    |}
    |
    |/* the correct twin: a fresh allocation of each length */
    |void allocate_every_iteration(const char *s, const unsigned *lens, int count, char **out)
    |{
    |    for (int i = 0; i < count; i++) {
    |        unsigned n = *lens;
    |        lens++;
    |        char *d = (char *)malloc(n);
    |        memcpy(d, s, n);
    |        out[i] = d;
    |    }
    |}
    |
    |/* the field is grown between the allocation and the copy */
    |void field_length_grown(const char *s, unsigned n, char **out)
    |{
    |    struct msg m;
    |    m.len = n;
    |    char *d = (char *)malloc(m.len);
    |    m.len += n;
    |    memcpy(d, s, m.len);
    |    *out = d;
    |}
    |
    |/* a field stored from the caller's length is the caller's length */
    |void field_length_unsized(const char *s, unsigned n, char **out)
    |{
    |    struct msg m;
    |    m.len = n;
    |    char *d = (char *)malloc(16);
    |    memcpy(d, s, m.len);
    |    *out = d;
    |}
    |
    |/* the correct twin: the same field value sizes the allocation and the copy */
    |void field_length_same(const char *s, unsigned n, char **out)
    |{
    |    struct msg m;
    |    m.len = n;
    |    char *d = (char *)malloc(m.len);
    |    memcpy(d, s, m.len);
    |    *out = d;
    |}
    |
    |/* the header is in both the size and the offset under the same condition */
    |int correlated_header(AVPacket *pkt, const unsigned char *buf, int len, int start_bit,
    |                      const unsigned char *nal_header, int nal_header_len)
    |{
    |    int ret;
    |    int tot_len = len;
    |    int pos = 0;
    |    if (start_bit)
    |        tot_len += sizeof(start_sequence) + nal_header_len;
    |    if ((ret = av_new_packet(pkt, tot_len)) < 0)
    |        return ret;
    |    if (start_bit) {
    |        memcpy(pkt->data + pos, start_sequence, sizeof(start_sequence));
    |        pos += sizeof(start_sequence);
    |        memcpy(pkt->data + pos, nal_header, nal_header_len);
    |        pos += nal_header_len;
    |    }
    |    memcpy(pkt->data + pos, buf, len);
    |    return 0;
    |}
    |
    |/* the size grows under one flag, the offset under another */
    |int uncorrelated_header(AVPacket *pkt, const unsigned char *buf, int len, int start_bit,
    |                        int other_bit, int nal_header_len)
    |{
    |    int ret;
    |    int tot_len = len;
    |    int pos = 0;
    |    if (start_bit)
    |        tot_len += nal_header_len;
    |    if ((ret = av_new_packet(pkt, tot_len)) < 0)
    |        return ret;
    |    if (other_bit)
    |        pos += nal_header_len;
    |    memcpy(pkt->data + pos, buf, len);
    |    return 0;
    |}
    |
    |/* the offset grows exactly when the size does not */
    |int inverted_header(AVPacket *pkt, const unsigned char *buf, int len, int start_bit,
    |                    int nal_header_len)
    |{
    |    int ret;
    |    int tot_len = len;
    |    int pos = 0;
    |    if (start_bit)
    |        tot_len += nal_header_len;
    |    if ((ret = av_new_packet(pkt, tot_len)) < 0)
    |        return ret;
    |    if (!start_bit)
    |        pos += nal_header_len;
    |    memcpy(pkt->data + pos, buf, len);
    |    return 0;
    |}
    |
    |/* the correct twin: a copy of the allocated pointer is the same buffer */
    |void through_a_copy(const char *s, unsigned n, char **out)
    |{
    |    char *p = (char *)malloc(n);
    |    char *d = p;
    |    memcpy(d, s, n);
    |    *out = d;
    |}
    |
    |/* the flexible member of an entry that may be another allocation */
    |void flexible_member_of_a_mixed_pointer(struct entry *small, const char *s, unsigned n, int c)
    |{
    |    struct entry *e = small;
    |    if (c)
    |        e = (struct entry *)malloc(sizeof(struct entry) - 1 + n);
    |    memcpy(e->data, s, n);
    |}
    |""".stripMargin,
    "self_sized_edges.cpp"
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
    "advanced_by_compound",
    "advanced_by_increment",
    "replaced_through_address",
    "sizeof_of_a_pointer",
    "sizeof_of_an_array_parameter",
    "guard_sum_wraps",
    "guard_else_exits",
    "length_changed_through_address",
    "global_keeps_its_value",
    "static_local_keeps_its_value",
    "shadowed",
    "copy_at_an_offset",
    "size_local_with_two_values",
    "copying_allocator",
    "calloc_with_a_variable_count",
    "appending_copy",
    "in_place_without_the_offset",
    "flexible_member_of_a_mixed_pointer",
    "packet_grow_wrong_offset",
    "reuse_first_allocation",
    "field_length_grown",
    "field_length_unsized",
    "uncorrelated_header",
    "inverted_header"
  )

  private val mustStaySilent = List(
    "copy_after_a_header",
    "calloc_of_one",
    "in_place_strip",
    "reused_in_a_loop",
    "through_a_copy",
    "header_then_body",
    "guard_by_early_exit",
    "allocate_every_iteration",
    "field_length_same",
    "correlated_header",
    "packet_after_header",
    "packet_grow_append",
    "in_place_compound",
    "offset_is_a_constant_local",
    "length_is_a_single_valued_local"
  )

  "the self-sized destination" should:
    mustFire.foreach { m =>
        s"report $m" in {
            findingsIn(m) should not be empty
        }
    }
    mustStaySilent.foreach { m =>
        s"stay silent on $m" in {
            findingsIn(m) shouldBe empty
        }
    }
end SelfSizedDestinationEdgeTests
