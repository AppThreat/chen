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
