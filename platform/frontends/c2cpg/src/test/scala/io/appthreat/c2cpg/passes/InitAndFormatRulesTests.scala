package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** MS-FMT-001 (CWE-134) and MS-INIT-001 (CWE-457). */
class InitAndFormatRulesTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdio.h>
    |#include <stdarg.h>
    |#include <syslog.h>
    |
    |void fmt_param(const char *u) { printf(u); }
    |void fmt_fprintf(const char *u) { fprintf(stderr, u); }
    |void fmt_snprintf(const char *u) { char b[8]; snprintf(b, sizeof(b), u); }
    |void fmt_syslog(const char *u) { syslog(LOG_INFO, u); }
    |void fmt_ok_literal(const char *u) { printf("%s", u); }
    |void fmt_local(const char *u) { const char *f = u; printf(f); }
    |void fmt_ok_local(int e) { const char *f = e ? "a %d" : "b %d"; printf(f, e); }
    |/* a forwarder: its callers' formats are what matters */
    |void my_log(const char *fmt, ...) { va_list vl; va_start(vl, fmt); vprintf(fmt, vl); va_end(vl); }
    |/* only ever called with literals */
    |static void say(const char *s) { printf(s); }
    |void callers(char **argv)
    |{
    |    say("hello\n");
    |    say("bye\n");
    |    fmt_param(argv[1]);
    |}
    |
    |int init_bad_scalar(void)
    |{
    |    int x;
    |    return x + 1;
    |}
    |struct S { int a; int b; };
    |int init_bad_field(void)
    |{
    |    struct S s;
    |    s.a = 1;
    |    return s.b;
    |}
    |int init_ok_field(void)
    |{
    |    struct S s;
    |    s.a = 1;
    |    return s.a;
    |}
    |#define GET_V(v, e) v = (e)
    |int init_ok_macro(int n)
    |{
    |    int x;
    |    GET_V(x, n + 1);
    |    return x;
    |}
    |int init_ok_av_uninit(int n)
    |{
    |    int x = x;
    |    if (n) x = 1;
    |    return n;
    |}
    |int init_ok_assigned(int n)
    |{
    |    int x;
    |    if (n) x = 1;
    |    else x = 2;
    |    return x;
    |}
    |int init_maybe(int n) /* one path initialises: not reported */
    |{
    |    int x;
    |    if (n) x = 1;
    |    return x;
    |}
    |int init_ok_out(void)
    |{
    |    int x;
    |    sscanf("1", "%d", &x);
    |    return x;
    |}
    |int init_ok_static(void)
    |{
    |    static int x;
    |    return x;
    |}
    |int init_ok_sizeof(void)
    |{
    |    int x;
    |    return (int)sizeof(x);
    |}
    |int init_ok_loop(int n)
    |{
    |    int x, i;
    |    for (i = 0; i < n; i++) {
    |        if (i)
    |            return x;
    |        x = i;
    |    }
    |    return 0;
    |}
    |int init_ok_whole(void)
    |{
    |    struct S s = {0};
    |    return s.b;
    |}
    |int init_bad_local_struct(void)
    |{
    |    struct T { int a; int b; } s;
    |    s.a = 1;
    |    return s.b;
    |}
    |int init_ok_local_struct(void)
    |{
    |    struct U { int a; int b; } s;
    |    s.a = 1;
    |    s.b = 2;
    |    return s.a + s.b;
    |}
    |int init_ok_local_struct_addr(void)
    |{
    |    struct V { int a; int b; } s;
    |    sscanf("1 2", "%d %d", &s.a, &s.b);
    |    return s.b;
    |}
    |int init_ok_local_whole_read(void)
    |{
    |    struct W { int a; int b; } s;
    |    s.a = 1;
    |    return s.a + s.a;
    |}
    |""".stripMargin,
    "rules.c"
  ).moreCode(
    """
    |int may_throw(int x);
    |int init_ok_catch(int x)
    |{
    |    int caught = 0;
    |    try { may_throw(x); }
    |    catch (int e) { caught = e; }
    |    catch (...) { caught = -1; }
    |    return caught;
    |}
    |int init_bad_in_handler(int x)
    |{
    |    try { may_throw(x); }
    |    catch (int e) {
    |        int y;
    |        return y + e;
    |    }
    |    return 0;
    |}
    |""".stripMargin,
    "handlers.cpp"
  ).moreCode(
    """
    |class Key {
    | public:
    |  Key() : n(0) {}
    |  void Clear() { n = 0; }
    | private:
    |  int n;
    |};
    |struct Output { unsigned long number; Key smallest, largest; };
    |struct Batch { Output outputs[2]; };
    |struct Plain { unsigned long number; unsigned long size; };
    |int init_ok_constructed_member(unsigned long v)
    |{
    |    Output out;
    |    out.number = v;
    |    out.smallest.Clear();
    |    out.largest.Clear();
    |    return (int)out.number;
    |}
    |int init_ok_constructed_array_member(unsigned long v)
    |{
    |    Batch b;
    |    b.outputs[0].smallest.Clear();
    |    return (int)v;
    |}
    |struct Block { unsigned int s[4]; unsigned int tag; };
    |extern "C" void *memcpy(void *, const void *, unsigned long);
    |Block init_ok_array_member_filled(const void *from)
    |{
    |    Block result;
    |    memcpy(result.s, from, sizeof(result.s));
    |    result.tag = result.s[0];
    |    return result;
    |}
    |int init_ok_written_by_lambda(int key)
    |{
    |    int index;
    |    bool inserted;
    |    [&]() {
    |        index = key * 2;
    |        inserted = true;
    |    }();
    |    return inserted ? index : -1;
    |}
    |struct Moments { unsigned long n = 0; double mean{0.0}; };
    |double init_ok_default_initialised(double x)
    |{
    |    Moments m;
    |    m.n++;
    |    m.mean += x;
    |    return m.mean / (double)m.n;
    |}
    |int init_bad_plain_member(unsigned long v)
    |{
    |    Plain p;
    |    p.number = v;
    |    return (int)p.size;
    |}
    |""".stripMargin,
    "members.cpp"
  ).moreCode(
    """
    |extern void *memcpy(void *, const void *, unsigned long);
    |union Ptrs { long *to_long; unsigned long *to_ulong; };
    |unsigned long union_store_other_member(long *src)
    |{
    |    union Ptrs p;
    |    p.to_long = src;
    |    return *p.to_ulong;
    |}
    |unsigned long union_anon_store_other_member(long *src)
    |{
    |    union { long *to_long; unsigned long *to_ulong; } p;
    |    p.to_long = src;
    |    return *p.to_ulong;
    |}
    |/* a store a macro's statement-expression block makes through its argument copy: the copy
    |       names the macro's parameter, the storage is the union member the caller passes */
    |#define word_copy(to, n, from, m) (((n) & 1) ? (to[(n) / 2] |= (from[(m) / 2] & 0xffffffff00000000UL)) : (to[(n) / 2] = (from[(m) / 2])))
    |#define word_set2(to, from, a2) { word_copy(to, 0, from, (a2) - 7); }
    |unsigned long union_macro_block_store(const unsigned long *src)
    |{
    |    union { unsigned long bn[4]; unsigned int ui[8]; } buf;
    |    word_set2(buf.bn, src, 9);
    |    return buf.bn[0];
    |}
    |unsigned union_bad_read_named(void)
    |{
    |    union Reinterp { float f; unsigned u; };
    |    union Reinterp b;
    |    return b.u;
    |}
    |unsigned union_bad_read_anon(void)
    |{
    |    union { float f; unsigned u; } b;
    |    return b.u;
    |}
    |unsigned long long union_bytes_then_words(const unsigned char *iv)
    |{
    |    union { unsigned long long q[2]; unsigned char c[16]; } tweak;
    |    memcpy(tweak.c, iv, 16);
    |    return tweak.q[0] ^ tweak.q[1];
    |}
    |unsigned long long union_element_store_then_read(unsigned seed)
    |{
    |    union { unsigned long long q[2]; unsigned char c[16]; } s;
    |    s.q[0] = seed;
    |    return s.q[1] ^ s.c[15];
    |}
    |struct WithUnion { int other; union { int a; float b; } u; };
    |int union_member_of_struct(int seed)
    |{
    |    struct WithUnion s;
    |    s.u.a = seed;
    |    return (int)s.u.b;
    |}
    |int union_member_of_struct_other(int seed)
    |{
    |    struct WithUnion s;
    |    s.u.a = seed;
    |    return s.other;
    |}
    |struct AnonUnion { int k; union { int a; float b; }; };
    |int union_anon_member_of_struct(int seed)
    |{
    |    struct AnonUnion s;
    |    s.a = seed;
    |    return (int)s.b;
    |}
    |union HoldsStruct { struct { int a; int b; } s; unsigned long long raw; };
    |int union_holds_struct(int seed)
    |{
    |    union HoldsStruct u;
    |    u.raw = 1;
    |    return u.s.a;
    |}
    |typedef void (*block_fn)(unsigned char *, unsigned char *, const void *);
    |union TweakU { unsigned long long q[2]; unsigned char c[16]; };
    |unsigned long long union_callee_writes(block_fn f)
    |{
    |    union TweakU tweak;
    |    f(tweak.c, tweak.c, 0);
    |    return tweak.q[0] ^ tweak.q[1];
    |}
    |struct Ctx { unsigned long long w[8]; };
    |typedef void (*ctx_init_fn)(struct Ctx *);
    |unsigned long long union_callee_writes_through_cast(ctx_init_fn f)
    |{
    |    union { unsigned char c[64]; unsigned long long q[8]; } md;
    |    f((struct Ctx *)md.c);
    |    return md.q[0];
    |}
    |typedef void (*offset_fn)(unsigned char *);
    |unsigned long long union_callee_writes_at_offset(offset_fn g)
    |{
    |    union { unsigned char c[32]; unsigned long long q[4]; } t;
    |    g(t.c + 16);
    |    return t.q[0];
    |}
    |#define CLEAR(u) __builtin_memset((u).c, 0, 16)
    |unsigned long long union_macro_callee_writes(void)
    |{
    |    union TweakU t;
    |    CLEAR(t);
    |    return t.q[0] ^ t.q[1];
    |}
    |unsigned long long union_bad_read_in_expression(void)
    |{
    |    union TweakU t;
    |    return t.q[0] + 1;
    |}
    |unsigned consume_bits(unsigned);
    |unsigned union_bad_read_by_value(void)
    |{
    |    union { float f; unsigned u; } b;
    |    return consume_bits(b.u);
    |}
    |unsigned union_bad_compound_first(unsigned v)
    |{
    |    union { unsigned w[2]; unsigned char c[8]; } u;
    |    u.w[0] |= v;
    |    return u.w[0];
    |}
    |long lookup_long(long *);
    |long union_bad_pointer_member_by_value(void)
    |{
    |    union Ptrs p;
    |    return lookup_long(p.to_long);
    |}
    |#define SLOT(i) XX##i
    |int init_ok_macro_lhs_store(int v)
    |{
    |    int XX0;
    |    SLOT(0) = v;
    |    return XX0;
    |}
    |int init_bad_macro_value_read(void)
    |{
    |    int XX9;
    |    return SLOT(9);
    |}
    |#define AT(i) slots[i]
    |int init_bad_macro_lhs_index(int v)
    |{
    |    int k;
    |    int slots[4];
    |    AT(k) = v;
    |    return slots[0];
    |}
    |typedef unsigned int fe[10];
    |typedef struct { fe yplusx; fe yminusx; } ge;
    |void fe_copy(fe dst, const fe src);
    |int init_ok_array_member_through_typedef(void)
    |{
    |    ge g;
    |    fe_copy(g.yplusx, g.yminusx);
    |    return (int)g.yplusx[0];
    |}
    |typedef struct { int x; int y; } pair_t;
    |int init_bad_typedef_record_member(int v)
    |{
    |    pair_t p;
    |    p.x = v;
    |    return p.y;
    |}
    |/* a branch a constant condition does not take is on no path */
    |int dead_branch_read_in_dead_then(int v)
    |{
    |    int x;
    |    if (0) { return x; }
    |    x = v;
    |    return x;
    |}
    |int dead_branch_write_in_dead_branch(int v)
    |{
    |    int x;
    |    if (0) { x = v; }
    |    return x;
    |}
    |int dead_branch_read_in_dead_else(int v)
    |{
    |    int x;
    |    if (1) { x = v; } else { return x; }
    |    return x;
    |}
    |int dead_branch_dead_loop_body(int v)
    |{
    |    int x;
    |    while (0) { return x; }
    |    x = v;
    |    return x;
    |}
    |#define DEAD_ZERO 0
    |int dead_branch_macro_condition(int v)
    |{
    |    int x;
    |    if (DEAD_ZERO) { return x; }
    |    x = v;
    |    return x;
    |}
    |int dead_branch_ternary(int v)
    |{
    |    int a;
    |    int r = (0 & 1) ? (a |= 5) : (a = 7);
    |    return r + a;
    |}
    |#define cp_naked(to, n, m) (((n) & 1) ? (to[(n) / 2] |= ((m) & 1) ? 5 : 6) : (to[(n) / 2] = ((m) & 1) ? 7 : 8))
    |int dead_branch_macro_ternary(const unsigned long *cd)
    |{
    |    union { unsigned long bn[4]; unsigned int ui[8]; } buf;
    |    cp_naked(buf.bn, 0, 1);
    |    return (int)buf.bn[0];
    |}
    |int dead_branch_for_body(int v)
    |{
    |    int x;
    |    for (; 0;) { return x; }
    |    x = v;
    |    return x;
    |}
    |/* the live twins: the same shapes with a condition a caller controls, and a dead branch a
    |   goto enters */
    |int live_branch_entered_by_goto(int v)
    |{
    |    int x;
    |    if (v) goto in;
    |    if (0) { in: return x; }
    |    x = v;
    |    return x;
    |}
    |int live_branch_read_in_then(int v)
    |{
    |    int x;
    |    if (v) { return x; }
    |    x = v;
    |    return x;
    |}
    |int live_branch_ternary(int v)
    |{
    |    int a;
    |    int r = (v & 1) ? (a |= 5) : (a = 7);
    |    return r + a;
    |}
    |int live_branch_macro_ternary(int v, const unsigned long *cd)
    |{
    |    union { unsigned long bn[4]; unsigned int ui[8]; } buf;
    |    cp_naked(buf.bn, v, 1);
    |    return (int)buf.bn[0];
    |}
    |""".stripMargin,
    "unions.c"
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

  "MS-FMT-001" should:
    "report a non-constant format in each printf-family position" in {
        Seq("fmt_param", "fmt_fprintf", "fmt_snprintf", "fmt_syslog", "fmt_local").foreach { m =>
            withClue(m) { findingsIn(m) should contain("MS-FMT-001") }
        }
    }
    "leave literal, literal-only locals, forwarders and literal-only callers alone" in {
        Seq("fmt_ok_literal", "fmt_ok_local", "my_log", "say").foreach { m =>
            withClue(m) { findingsIn(m) should not contain "MS-FMT-001" }
        }
    }

  "MS-INIT-001" should:
    "report a local and a member no path initialises" in {
        findingsIn("init_bad_scalar") should contain("MS-INIT-001")
        findingsIn("init_bad_field") should contain("MS-INIT-001")
    }
    "report a member of a struct declared inside the function" in {
        findingsIn("init_bad_local_struct") should contain("MS-INIT-001")
    }
    "leave a fully-written in-function struct, an address-taken one and whole-value reads alone" in {
        Seq("init_ok_local_struct", "init_ok_local_struct_addr", "init_ok_local_whole_read").foreach {
            m =>
                withClue(m) { findingsIn(m) should not contain "MS-INIT-001" }
        }
    }
    "leave initialised, out-param, static, sizeof, loop-carried and maybe-initialised reads alone" in {
        Seq(
          "init_ok_field",
          "init_ok_assigned",
          "init_maybe",
          "init_ok_out",
          "init_ok_static",
          "init_ok_sizeof",
          "init_ok_loop",
          "init_ok_whole",
          "init_ok_macro",
          "init_ok_av_uninit"
        ).foreach { m => withClue(m) { findingsIn(m) should not contain "MS-INIT-001" } }
    }
    "treat a catch handler's exception as initialised, but not the handler's own locals" in {
        findingsIn("init_ok_catch") should not contain "MS-INIT-001"
        findingsIn("init_bad_in_handler") should contain("MS-INIT-001")
        cpg.method.nameExact("init_bad_in_handler").ast.isIdentifier
            .filter(_.tag.nameExact("ms-finding").value.l.contains("MS-INIT-001"))
            .name.l shouldBe List("y")
    }
    "leave a struct whose members a constructor initialises alone, but not a plain one" in {
        findingsIn("init_ok_constructed_member") should not contain "MS-INIT-001"
        findingsIn("init_ok_constructed_array_member") should not contain "MS-INIT-001"
        findingsIn("init_bad_plain_member") should contain("MS-INIT-001")
    }
    "leave a local a lambda captures alone" in {
        findingsIn("init_ok_written_by_lambda") should not contain "MS-INIT-001"
    }
    "leave a struct holding an array, or one whose members have initialisers, alone" in {
        findingsIn("init_ok_array_member_filled") should not contain "MS-INIT-001"
        findingsIn("init_ok_default_initialised") should not contain "MS-INIT-001"
    }
    "treat a union's members as one storage" in {
        Seq(
          "union_store_other_member",
          "union_anon_store_other_member",
          "union_macro_block_store",
          "union_bytes_then_words",
          "union_element_store_then_read",
          "union_member_of_struct",
          "union_anon_member_of_struct",
          "union_holds_struct",
          "union_callee_writes",
          "union_callee_writes_through_cast",
          "union_callee_writes_at_offset",
          "union_macro_callee_writes"
        ).foreach { m => withClue(m) { findingsIn(m) should not contain "MS-INIT-001" } }
        findingsIn("union_member_of_struct_other") should contain("MS-INIT-001")
        findingsIn("union_bad_read_in_expression") should contain("MS-INIT-001")
    }
    "report a union member nothing initialises" in {
        findingsIn("union_bad_read_named") should contain("MS-INIT-001")
        findingsIn("union_bad_read_anon") should contain("MS-INIT-001")
    }
    "report a union member read by value: passed to a call, or by a compound assignment" in {
        findingsIn("union_bad_read_by_value") should contain("MS-INIT-001")
        findingsIn("union_bad_pointer_member_by_value") should contain("MS-INIT-001")
        findingsIn("union_bad_compound_first") should contain("MS-INIT-001")
    }
    "treat a macro invocation on a store's left side as the store it expands to" in {
        findingsIn("init_ok_macro_lhs_store") should not contain "MS-INIT-001"
        findingsIn("init_bad_macro_value_read") should contain("MS-INIT-001")
    }
    "still report what such a macro's expansion only reads, as an index" in {
        findingsIn("init_bad_macro_lhs_index") should contain("MS-INIT-001")
    }
    "leave a struct whose member is an array through a typedef alone" in {
        findingsIn("init_ok_array_member_through_typedef") should not contain "MS-INIT-001"
    }
    "report a member of a typedef'd record nothing initialises" in {
        findingsIn("init_bad_typedef_record_member") should contain("MS-INIT-001")
    }
    "not read a branch a constant condition never takes" in {
        Seq(
          "dead_branch_read_in_dead_then",
          "dead_branch_read_in_dead_else",
          "dead_branch_dead_loop_body",
          "dead_branch_for_body",
          "dead_branch_macro_condition",
          "dead_branch_ternary",
          "dead_branch_macro_ternary"
        ).foreach { m => withClue(m) { findingsIn(m) should not contain "MS-INIT-001" } }
    }
    "still report the same shapes on a branch a caller controls, and a write only a dead branch makes" in {
        Seq(
          "dead_branch_write_in_dead_branch",
          "live_branch_read_in_then",
          "live_branch_entered_by_goto",
          "live_branch_ternary",
          "live_branch_macro_ternary"
        ).foreach { m => withClue(m) { findingsIn(m) should contain("MS-INIT-001") } }
    }
end InitAndFormatRulesTests

/** A printf-family function defined as a macro over its checked builtin, as C libraries do under
  * `_FORTIFY_SOURCE`: one finding, on the macro's call.
  */
class FortifiedFormatTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
      |typedef unsigned long size_t;
      |int __builtin___snprintf_chk(char *, size_t, int, size_t, const char *, ...);
      |#define snprintf(buf, len, ...) \
      |    __builtin___snprintf_chk(buf, len, 0, __builtin_object_size(buf, 0), __VA_ARGS__)
      |void fortified(const char *userInput) {
      |    char buf[64];
      |    snprintf(buf, sizeof(buf), userInput);
      |}
      |""".stripMargin,
    "fortified.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  "a non-constant format through the macro" should {
      "be reported once" in {
          cpg.method.nameExact("fortified").ast.collectAll[StoredNode]
              .flatMap(_.tag.nameExact("ms-finding").value.l).l.count(_ == "MS-FMT-001") shouldBe 1
      }
  }
end FortifiedFormatTests
