package io.appthreat.edg2atom.passes

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.edg2atom.testfixtures.DefaultTestCpgWithEdg
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.taggers.*
import io.appthreat.x2cpg.testfixtures.Code2CpgFixture
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

class EdgDataFlowTestCpg extends DefaultTestCpgWithEdg(".cpp"):
  override protected def applyPasses(): Unit =
    X2Cpg.applyDefaultOverlays(this)
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(this))

/** The memory-safety rules over the graph edga's C++ gives: the shapes a front end that resolves
  * every name and type produces (a constant's value, a typedef's scope, a struct's members, scoped
  * guards, structured bindings) read as the code means them.
  */
class MemorySafetyOnEdgTests extends Code2CpgFixture(() => new EdgDataFlowTestCpg()):

  private val edgaAvailable = EdgaRunner.locate().isDefined

  private lazy val cpg =
    val graph = code(
      """
      |#include <algorithm>
      |#include <cassert>
      |#include <cstddef>
      |#include <cstring>
      |#include <mutex>
      |#include <string>
      |#include <thread>
      |#include <vector>
      |
      |namespace demo {
      |namespace {
      |constexpr const size_t kBufferSize = 65536;
      |}
      |
      |class Writer {
      | public:
      |  void Append(const char *data, size_t n) {
      |    size_t copy_size = std::min(n, kBufferSize - pos_);
      |    std::memcpy(buf_ + pos_, data, copy_size);
      |    pos_ += copy_size;
      |  }
      | private:
      |  char buf_[kBufferSize];
      |  size_t pos_ = 0;
      |};
      |
      |class Key {
      | public:
      |  Key() {}
      |  void Clear() { rep_.clear(); }
      | private:
      |  std::string rep_;
      |};
      |struct Output { unsigned long number; Key smallest, largest; };
      |struct Plain { unsigned long number; unsigned long size; };
      |
      |std::vector<Output> outputs;
      |void open_output(unsigned long n) {
      |  Output out;
      |  out.number = n;
      |  out.smallest.Clear();
      |  outputs.push_back(out);
      |}
      |unsigned long plain_read(unsigned long n) {
      |  Plain p;
      |  p.number = n;
      |  return p.size;
      |}
      |
      |void create_filter(int n, std::string *dst) {
      |  size_t bytes = (static_cast<size_t>(n) * 10 + 7) / 8;
      |  const size_t init_size = dst->size();
      |  dst->resize(init_size + bytes, 0);
      |  char *array = &(*dst)[init_size];
      |  array[0] = 1;
      |}
      |
      |struct Version { std::vector<int *> files_[7]; };
      |int level_files(const Version *v, int level) { return (int)v->files_[level].size(); }
      |
      |std::mutex &freelist_mutex() { static std::mutex mu; return mu; }
      |class MutexLock {
      | public:
      |  explicit MutexLock(std::mutex &m) : m_(m) { m_.lock(); }
      |  ~MutexLock() { m_.unlock(); }
      | private:
      |  std::mutex &m_;
      |};
      |std::vector<void *> *s_freelist = nullptr;
      |int counter = 0;
      |void add_to_freelist(void *p) {
      |  MutexLock l(freelist_mutex());
      |  if (!s_freelist) {
      |    s_freelist = new std::vector<void *>;
      |  }
      |  s_freelist->push_back(p);
      |}
      |void bump() {
      |  if (counter == 0) {
      |    counter = 1;
      |  }
      |}
      |void start() { std::thread t([] { add_to_freelist(nullptr); bump(); }); t.join(); }
      |
      |struct Data { int manipulated = 0; };
      |class View {
      | public:
      |  explicit View(Data &d) : d_(d) { d_.manipulated++; }
      |  ~View() { d_.manipulated--; }
      | private:
      |  Data &d_;
      |};
      |class LogMessage {
      | public:
      |  LogMessage &operator<<(int v) {
      |    View view(*data_);
      |    data_->manipulated += v;
      |    return *this;
      |  }
      | private:
      |  Data *data_ = nullptr;
      |};
      |
      |struct Span { char *data; size_t size; };
      |Span make_span(char *p, size_t n);
      |size_t split(char *p, size_t n) {
      |  assert(n > 0);
      |  auto [data, size] = make_span(p, n);
      |  return static_cast<size_t>(data[0]) + size;
      |}
      |
      |struct alignas(16) Vector128 { unsigned int s[4]; };
      |Vector128 load(const void *from) {
      |  Vector128 result;
      |  std::memcpy(result.s, from, sizeof(Vector128));
      |  return result;
      |}
      |
      |struct Moments { size_t n = 0; double mean = 0.0; };
      |double moments(const double *xs, size_t count) {
      |  Moments m;
      |  for (size_t i = 0; i < count; i++) {
      |    m.n++;
      |    m.mean += xs[i];
      |  }
      |  return m.mean / static_cast<double>(m.n);
      |}
      |
      |enum SynchEvent { kLock, kTryLock, kUnlock, kWait };
      |static const struct { int flags; const char *msg; } event_properties[] = {
      |    {1, "lock"}, {2, "trylock"}, {3, "unlock"}, {4, "wait"}};
      |int event_flags(SynchEvent ev) { return event_properties[ev].flags; }
      |
      |template <class T> unsigned long hash_bytes(const T &value) {
      |  unsigned long v;
      |  if constexpr (sizeof(T) == 1) {
      |    v = 1;
      |  } else if constexpr (sizeof(T) == 2) {
      |    v = 2;
      |  } else {
      |    v = 8;
      |  }
      |  return v + static_cast<unsigned long>(value);
      |}
      |unsigned long hash_long(long x) { return hash_bytes(x); }
      |
      |int find_slot(int key) {
      |  int index;
      |  bool inserted;
      |  [&]() {
      |    index = key * 2;
      |    inserted = true;
      |  }();
      |  return inserted ? index : -1;
      |}
      |
      |enum { EV_LOCK, EV_READERLOCK, EV_UNLOCK, EV_READERUNLOCK };
      |static const struct { int flags; const char *msg; } synch_properties[] = {
      |    {1, "lock"}, {2, "readerlock"}, {3, "unlock"}, {4, "readerunlock"}};
      |static int post_event(int ev) { return synch_properties[ev].flags; }
      |int lock_event(bool exclusive) { return post_event(exclusive ? EV_LOCK : EV_READERLOCK); }
      |int unlock_event() { return post_event(EV_UNLOCK); }
      |
      |class CharSpan {
      | public:
      |  CharSpan(char *p, size_t n) : ptr_(p), len_(n) {}
      |  char *data() const { return ptr_; }
      |  size_t size() const { return len_; }
      | private:
      |  char *ptr_;
      |  size_t len_;
      |};
      |size_t copy_to_span(const std::vector<std::string> &chunks, CharSpan dst) {
      |  size_t copied = 0;
      |  for (const std::string &chunk : chunks) {
      |    size_t n = std::min(chunk.size(), dst.size());
      |    if (n == 0) break;
      |    std::memcpy(dst.data(), chunk.data(), n);
      |    copied += n;
      |  }
      |  return copied;
      |}
      |size_t copy_to_other_span(const std::vector<std::string> &chunks, CharSpan dst, CharSpan limit) {
      |  size_t copied = 0;
      |  for (const std::string &chunk : chunks) {
      |    size_t n = std::min(chunk.size(), limit.size());
      |    if (n == 0) break;
      |    std::memcpy(dst.data(), chunk.data(), n);
      |    copied += n;
      |  }
      |  return copied;
      |}
      |
      |unsigned short add_counts(unsigned short a, unsigned short b) {
      |  unsigned short s = a + b;
      |  long wide = s;
      |  return static_cast<unsigned short>(wide);
      |}
      |
      |template <class T> struct Limits { static const int digits = 64; };
      |int digits_of() {
      |  int width = Limits<long>::digits / 4;
      |  int digits = width + 1;
      |  return digits;
      |}
      |}
      |
      |#define SOCK_IDX_VALID(i) (((i) >= 0) && ((i) < 2))
      |#define FIRST_SOCKET 0
      |#define SECOND_SOCKET 1
      |struct Conn { int *filters[2]; long started[2]; };
      |int *filter_of(Conn *conn, int sockindex) {
      |  return SOCK_IDX_VALID(sockindex) ? conn->filters[sockindex] : nullptr;
      |}
      |static void clear_timer(Conn *conn, signed char sockindex) { conn->started[sockindex] = -1; }
      |void clear_timers(Conn *conn) {
      |  clear_timer(conn, FIRST_SOCKET);
      |  clear_timer(conn, SECOND_SOCKET);
      |}
      |""".stripMargin,
      "shapes.cpp"
    ).moreCode(
      """
      |extern "C" void *memcpy(void *, const void *, unsigned long);
      |union Ptrs { long *to_long; unsigned long *to_ulong; };
      |unsigned long union_store_other_member(long *src) {
      |  union Ptrs p;
      |  p.to_long = src;
      |  return *p.to_ulong;
      |}
      |unsigned long union_anon_store_other_member(long *src) {
      |  union { long *to_long; unsigned long *to_ulong; } p;
      |  p.to_long = src;
      |  return *p.to_ulong;
      |}
      |unsigned union_bad_read_named() {
      |  union Reinterp { float f; unsigned u; };
      |  union Reinterp b;
      |  return b.u;
      |}
      |unsigned union_bad_read_anon() {
      |  union { float f; unsigned u; } b;
      |  return b.u;
      |}
      |unsigned long long union_bytes_then_words(const unsigned char *iv) {
      |  union { unsigned long long q[2]; unsigned char c[16]; } tweak;
      |  memcpy(tweak.c, iv, 16);
      |  return tweak.q[0] ^ tweak.q[1];
      |}
      |unsigned long long union_element_store_then_read(unsigned seed) {
      |  union { unsigned long long q[2]; unsigned char c[16]; } s;
      |  s.q[0] = seed;
      |  return s.q[1] ^ s.c[15];
      |}
      |struct WithUnion { int other; union { int a; float b; } u; };
      |int union_member_of_struct(int seed) {
      |  struct WithUnion s;
      |  s.u.a = seed;
      |  return (int)s.u.b;
      |}
      |int union_member_of_struct_other(int seed) {
      |  struct WithUnion s;
      |  s.u.a = seed;
      |  return s.other;
      |}
      |struct AnonUnion { int k; union { int a; float b; }; };
      |int union_anon_member_of_struct(int seed) {
      |  struct AnonUnion s;
      |  s.a = seed;
      |  return (int)s.b;
      |}
      |union HoldsStruct { struct { int a; int b; } s; unsigned long long raw; };
      |int union_holds_struct(int seed) {
      |  union HoldsStruct u;
      |  u.raw = 1;
      |  return u.s.a;
      |}
      |typedef void (*block_fn)(unsigned char *, unsigned char *, const void *);
      |union TweakU { unsigned long long q[2]; unsigned char c[16]; };
      |unsigned long long union_callee_writes(block_fn f) {
      |  union TweakU tweak;
      |  f(tweak.c, tweak.c, 0);
      |  return tweak.q[0] ^ tweak.q[1];
      |}
      |struct Ctx { unsigned long long w[8]; };
      |typedef void (*ctx_init_fn)(struct Ctx *);
      |unsigned long long union_callee_writes_through_cast(ctx_init_fn f) {
      |  union { unsigned char c[64]; unsigned long long q[8]; } md;
      |  f((struct Ctx *)md.c);
      |  return md.q[0];
      |}
      |typedef void (*offset_fn)(unsigned char *);
      |unsigned long long union_callee_writes_at_offset(offset_fn g) {
      |  union { unsigned char c[32]; unsigned long long q[4]; } t;
      |  g(t.c + 16);
      |  return t.q[0];
      |}
      |#define CLEAR(u) __builtin_memset((u).c, 0, 16)
      |unsigned long long union_macro_callee_writes() {
      |  union TweakU t;
      |  CLEAR(t);
      |  return t.q[0] ^ t.q[1];
      |}
      |unsigned long long union_bad_read_in_expression() {
      |  union TweakU t;
      |  return t.q[0] + 1;
      |}
      |unsigned consume_bits(unsigned);
      |unsigned union_bad_read_by_value() {
      |  union { float f; unsigned u; } b;
      |  return consume_bits(b.u);
      |}
      |unsigned union_bad_compound_first(unsigned v) {
      |  union { unsigned w[2]; unsigned char c[8]; } u;
      |  u.w[0] |= v;
      |  return u.w[0];
      |}
      |long lookup_long(long *);
      |long union_bad_pointer_member_by_value() {
      |  union Ptrs p;
      |  return lookup_long(p.to_long);
      |}
      |#define SLOT(i) XX##i
      |int init_ok_macro_lhs_store(int v) {
      |  int XX0;
      |  SLOT(0) = v;
      |  return XX0;
      |}
      |int init_bad_macro_value_read() {
      |  int XX9;
      |  return SLOT(9);
      |}
      |#define SET_FLAG(flag, v) { int t_ = (v); flag = t_ > 0; if (t_ > 9) flag = 0; }
      |int init_ok_block_macro_store(int v) {
      |  int flag;
      |  SET_FLAG(flag, v);
      |  return flag;
      |}
      |int fetch_info(int h, int *out);
      |#define GET_INFO(h, out) __extension__({ fetch_info(h, out); })
      |int init_ok_statement_expression_out_param(int h) {
      |  int info;
      |  GET_INFO(h, &info);
      |  return info;
      |}
      |int fill_info(int *out, int a, int b, int c);
      |#define FILL_INFO(out, ...) fill_info(out, __VA_ARGS__)
      |int init_ok_variadic_macro_out_param(int a) {
      |  int info;
      |  FILL_INFO(&info, a, 2, 3);
      |  return info;
      |}
      |#define NOTE(v) { int n_ = (v); (void)n_; }
      |int init_bad_read_after_block_macro(int v) {
      |  int flag;
      |  NOTE(v);
      |  return flag;
      |}
      |typedef unsigned int fe[10];
      |typedef struct { fe yplusx; fe yminusx; } ge;
      |void fe_copy(fe dst, const fe src);
      |int init_ok_array_member_through_typedef() {
      |  ge g;
      |  fe_copy(g.yplusx, g.yminusx);
      |  return (int)g.yplusx[0];
      |}
      |typedef struct { int x; int y; } pair_t;
      |int init_bad_typedef_record_member(int v) {
      |  pair_t p;
      |  p.x = v;
      |  return p.y;
      |}
      |/* a branch a constant condition does not take is on no path */
      |int dead_branch_read_in_dead_then(int v) {
      |  int x;
      |  if (0) { return x; }
      |  x = v;
      |  return x;
      |}
      |int dead_branch_read_in_dead_else(int v) {
      |  int x;
      |  if (1) { x = v; } else { return x; }
      |  return x;
      |}
      |int dead_branch_for_body(int v) {
      |  int x;
      |  for (; 0;) { return x; }
      |  x = v;
      |  return x;
      |}
      |int live_branch_entered_by_goto(int v) {
      |  int x;
      |  if (v) goto in;
      |  if (0) { in: return x; }
      |  x = v;
      |  return x;
      |}
      |int dead_branch_write_in_dead_branch(int v) {
      |  int x;
      |  if (0) { x = v; }
      |  return x;
      |}
      |#define DEAD_ZERO 0
      |int dead_branch_macro_condition(int v) {
      |  int x;
      |  if (DEAD_ZERO) { return x; }
      |  x = v;
      |  return x;
      |}
      |#define cp_naked(to, n, m) (((n) & 1) ? (to[(n) / 2] |= ((m) & 1) ? 5 : 6) : (to[(n) / 2] = ((m) & 1) ? 7 : 8))
      |int dead_branch_macro_ternary(const unsigned long *cd) {
      |  union { unsigned long bn[4]; unsigned int ui[8]; } buf;
      |  cp_naked(buf.bn, 0, 1);
      |  return (int)buf.bn[0];
      |}
      |int live_branch_ternary(int v) {
      |  int a;
      |  int r = (v & 1) ? (a |= 5) : (a = 7);
      |  return r + a;
      |}
      |int live_branch_macro_ternary(int v, const unsigned long *cd) {
      |  union { unsigned long bn[4]; unsigned int ui[8]; } buf;
      |  cp_naked(buf.bn, v, 1);
      |  return (int)buf.bn[0];
      |}
      |typedef long offset_like;
      |int bad_resign_guard_typedef(unsigned int obu_size, int remaining, unsigned char *dst,
      |                             const unsigned char *src) {
      |  if ((offset_like)obu_size > remaining)
      |    return -1;
      |  memcpy(dst, src, obu_size);
      |  return 0;
      |}
      |typedef enum { kOne, kTwo, kThree } count_t;
      |static const int count_props[3] = {1, 2, 3};
      |int props_of_typedef_enum(count_t c) { return count_props[c]; }
      |""".stripMargin,
      "unions.cpp"
    )
    new MemorySemanticsPass(graph).createAndApply()
    new MemoryApiPass(graph).createAndApply()
    new ExtentPass(graph).createAndApply()
    new GuardPass(graph).createAndApply()
    new ValueOriginPass(graph).createAndApply()
    new IntegerWidthPass(graph).createAndApply()
    new AllocationStatePass(graph).createAndApply()
    new MemorySafetyFindingPass(graph).createAndApply()
    graph
  end cpg

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  private def requireEdga(): Unit = assume(edgaAvailable, "edga is not installed")

  "a copy clamped against a buffer a constant sizes" should {
      "not be an unbounded copy" in {
          requireEdga()
          findingsIn("Append") should not contain "MS-BOUND-002"
      }
  }

  "a copy clamped against the size of the object it writes into" should {
      "not be an unbounded copy" in {
          requireEdga()
          findingsIn("copy_to_span") should not contain "MS-BOUND-002"
      }

      "still be one when the clamp is against another object" in {
          requireEdga()
          findingsIn("copy_to_other_span") should contain("MS-BOUND-002")
      }
  }

  "a struct" should {
      "be initialised by the constructors of its members" in {
          requireEdga()
          findingsIn("open_output") should not contain "MS-INIT-001"
      }

      "be filled by a copy into its array member" in {
          requireEdga()
          findingsIn("load") should not contain "MS-INIT-001"
      }

      "be initialised by its members' default initialisers" in {
          requireEdga()
          findingsIn("moments") should not contain "MS-INIT-001"
      }

      "still report a plain member no path writes" in {
          requireEdga()
          findingsIn("plain_read") should contain("MS-INIT-001")
      }
  }

  "a union's members" should {
      "be one storage: a store to any member, or a member passed out, initialises them all" in {
          requireEdga()
          Seq(
            "union_store_other_member",
            "union_anon_store_other_member",
            "union_bytes_then_words",
            "union_element_store_then_read",
            "union_member_of_struct",
            "union_anon_member_of_struct",
            "union_holds_struct",
            "union_callee_writes",
            "union_callee_writes_through_cast",
            "union_callee_writes_at_offset",
            "union_macro_callee_writes"
          ).foreach { m =>
              withClue(m) { findingsIn(m) should not contain "MS-INIT-001" }
          }
          findingsIn("union_member_of_struct_other") should contain("MS-INIT-001")
          findingsIn("union_bad_read_in_expression") should contain("MS-INIT-001")
      }

      "still report a union member nothing initialises" in {
          requireEdga()
          findingsIn("union_bad_read_named") should contain("MS-INIT-001")
          findingsIn("union_bad_read_anon") should contain("MS-INIT-001")
      }

      "report a member read by value: passed to a call, or by a compound assignment" in {
          requireEdga()
          findingsIn("union_bad_read_by_value") should contain("MS-INIT-001")
          findingsIn("union_bad_pointer_member_by_value") should contain("MS-INIT-001")
          findingsIn("union_bad_compound_first") should contain("MS-INIT-001")
      }
  }

  "a macro invocation on a store's left side" should {
      "be the store it expands to, and a macro's value still a read" in {
          requireEdga()
          findingsIn("init_ok_macro_lhs_store") should not contain "MS-INIT-001"
          findingsIn("init_bad_macro_value_read") should contain("MS-INIT-001")
      }
  }

  "a macro invocation's expansion" should {
      "make the stores it runs, a variadic macro's out-parameter call's too" in {
          requireEdga()
          findingsIn("init_ok_variadic_macro_out_param") should not contain "MS-INIT-001"
      }
      "keep its argument copies as they are written" in {
          requireEdga()
          cpg.call.nameExact("FILL_INFO").argument.code.l shouldBe List("&info", "a", "2", "3")
      }
      "make them when it is a block or a statement expression" in {
          requireEdga()
          findingsIn("init_ok_block_macro_store") should not contain "MS-INIT-001"
          findingsIn("init_ok_statement_expression_out_param") should not contain "MS-INIT-001"
      }
      "still leave a variable it does not write unwritten" in {
          requireEdga()
          findingsIn("init_bad_read_after_block_macro") should contain("MS-INIT-001")
      }
  }

  "a struct whose member is an array through a typedef" should {
      "be left alone, as with a spelled-out array member" in {
          requireEdga()
          findingsIn("init_ok_array_member_through_typedef") should not contain "MS-INIT-001"
      }
  }

  "a member of a typedef'd record nothing initialises" should {
      "be reported as with a tagged record" in {
          requireEdga()
          findingsIn("init_bad_typedef_record_member") should contain("MS-INIT-001")
      }
  }

  "a branch a constant condition never takes" should {
      "prove nothing about the paths that run" in {
          requireEdga()
          Seq(
            "dead_branch_read_in_dead_then",
            "dead_branch_read_in_dead_else",
            "dead_branch_for_body",
            "dead_branch_macro_condition",
            "dead_branch_macro_ternary"
          ).foreach { m => withClue(m) { findingsIn(m) should not contain "MS-INIT-001" } }
      }

      "still count a write only it makes as no write, and a live condition's branch as live" in {
          requireEdga()
          findingsIn("dead_branch_write_in_dead_branch") should contain("MS-INIT-001")
          findingsIn("live_branch_ternary") should contain("MS-INIT-001")
          findingsIn("live_branch_entered_by_goto") should contain("MS-INIT-001")
          findingsIn("live_branch_macro_ternary") should contain("MS-INIT-001")
      }
  }

  "a guard over a re-signing cast to a typedef'd name" should {
      "cross signedness as the spelled-out cast does" in {
          requireEdga()
          findingsIn("bad_resign_guard_typedef") should contain("MS-INT-002")
      }
  }

  "a table indexed by an enum a typedef names without a tag" should {
      "not be indexed out of bounds" in {
          requireEdga()
          findingsIn("props_of_typedef_enum") should not contain "MS-BOUND-003"
      }
  }

  "a container" should {
      "not be indexed out of bounds past a resize that grew it past the index" in {
          requireEdga()
          findingsIn("create_filter") should not contain "MS-BOUND-003"
      }

      "not be an array of containers" in {
          requireEdga()
          findingsIn("level_files").intersect(Set("MS-BOUND-003")) shouldBe empty
      }
  }

  "a table indexed by an enumeration with one entry per enumerator" should {
      "not be indexed out of bounds" in {
          requireEdga()
          findingsIn("event_flags") should not contain "MS-BOUND-003"
      }
  }

  "a table indexed by what every caller passes, enumerators" should {
      "not be indexed out of bounds" in {
          requireEdga()
          findingsIn("post_event") should not contain "MS-BOUND-003"
      }
  }

  "a table indexed by what every caller passes, macro constants" should {
      "not be indexed out of bounds" in {
          requireEdga()
          findingsIn("clear_timer") should not contain "MS-BOUND-004"
      }
  }

  "an index a macro bounds in a conditional's condition" should {
      "not be indexed out of bounds" in {
          requireEdga()
          findingsIn("filter_of") should not contain "MS-BOUND-003"
      }
  }

  "a narrowing store" should {
      "be read from the conversion the frontend recorded" in {
          requireEdga()
          val narrow = cpg.method.nameExact("add_counts").ast.isCall.l
              .flatMap(c => c.tag.nameExact("int-narrow").value.l.map(c.code -> _))
          narrow should contain("s = a + b" -> "from:int:32->to:unsigned short:16")
          narrow.map(_._1) should not contain "wide = s"
      }
  }

  "a check-then-act on a global" should {
      "be safe under a scoped lock" in {
          requireEdga()
          findingsIn("add_to_freelist") should not contain "MS-TOCTOU-001"
      }

      "be reported without one" in {
          requireEdga()
          findingsIn("bump") should contain("MS-TOCTOU-001")
      }
  }

  "a reference return under a scoped object" should {
      "not escape the frame" in {
          requireEdga()
          findingsIn("operator <<") should not contain "MS-ESC-001"
      }
  }

  "a structured binding beside an assert" should {
      "read no unnamed local" in {
          requireEdga()
          findingsIn("split") should not contain "MS-INIT-001"
      }
  }

  "an `if constexpr` in a template instance" should {
      "be the branch it takes" in {
          requireEdga()
          findingsIn("hash_bytes") should not contain "MS-INIT-001"
      }
  }

  "a local a lambda captures by reference" should {
      "not be read uninitialised after the lambda writes it" in {
          requireEdga()
          findingsIn("find_slot") should not contain "MS-INIT-001"
      }
  }

  "a class's static member named like a later local" should {
      "not be a read of that local" in {
          requireEdga()
          findingsIn("digits_of") should not contain "MS-INIT-001"
      }
  }
end MemorySafetyOnEdgTests

/** A unit edga cannot export, parsed by the CDT frontend into the same graph: its locals of a class
  * template instance from a project header read that instance's TYPE_DECL, which edga's units wrote
  * without its member functions as children.
  */
class MemorySafetyWithFallbackTests extends org.scalatest.wordspec.AnyWordSpec
    with org.scalatest.matchers.should.Matchers:

  private val span = "span.h" ->
      """#pragma once
        |namespace demo {
        |template <class T> class Span {
        | public:
        |  Span(T *p, unsigned long n) : ptr_(p), len_(n) {}
        |  unsigned long size() const { return len_; }
        |  T *data() const { return ptr_; }
        | private:
        |  T *ptr_;
        |  unsigned long len_;
        |};
        |}
        |""".stripMargin
  private val user = "a.cpp" ->
      """#include "span.h"
        |namespace demo { unsigned long first(char *p, unsigned long n) { Span<char> s(p, n); return s.size(); } }
        |""".stripMargin
  // a header edga cannot find: the CDT frontend parses this unit
  private val fallback = "b.cpp" ->
      """#include "missing.h"
        |#include "span.h"
        |namespace demo {
        |unsigned long span_size(char *p, unsigned long n) {
        |  Span<char> buf(p, n);
        |  return buf.size();
        |}
        |}
        |""".stripMargin

  "a local of a class template instance" should {
      "be initialised by the instance's constructor" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          better.files.File.usingTemporaryDirectory("edg2atom") { dir =>
            Seq(span, user, fallback).foreach { (name, text) => (dir / name).writeText(text) }
            val out = better.files.File.newTemporaryFile("edg2atom", ".atom")
            val config = io.appthreat.c2cpg.Config().withInputPath(dir.pathAsString)
                .withOutputPath(out.pathAsString).withFunctionBodies(true).withAstCache(false)
            val cpg = new io.appthreat.edg2atom.Edg2Atom(true).createCpg(config).get
            try
              X2Cpg.applyDefaultOverlays(cpg)
              new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(cpg))
              new MemorySemanticsPass(cpg).createAndApply()
              new MemoryApiPass(cpg).createAndApply()
              new ExtentPass(cpg).createAndApply()
              new GuardPass(cpg).createAndApply()
              new ValueOriginPass(cpg).createAndApply()
              new IntegerWidthPass(cpg).createAndApply()
              new AllocationStatePass(cpg).createAndApply()
              new MemorySafetyFindingPass(cpg).createAndApply()
              cpg.method.nameExact("span_size").size shouldBe 1
              cpg.method.nameExact("span_size").ast.collectAll[StoredNode]
                  .flatMap(_.tag.nameExact("ms-finding").value.l).l should not contain "MS-INIT-001"
            finally
              cpg.close()
              out.delete(swallowIOExceptions = true)
          }
      }
  }
end MemorySafetyWithFallbackTests
