package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.Defines
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** Each variable says how it is referenced, and a guard on a variable whose address left is not
  * trusted across a write that can reach it unnamed.
  */
class ReferenceKindTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |void g(int *);
    |void use(int *);
    |void note(void);
    |int global_count;
    |int global_limit = 8;
    |
    |int kinds(int a, int b, int c)
    |{
    |    int n = 5, k, ro = 3;
    |    int arr[4];
    |    struct { int f; } s;
    |    int *p = &n;
    |    k = a;
    |    g(p);
    |    b += 1;
    |    arr[0] = 1;
    |    s.f = 2;
    |    use(arr);
    |    global_count++;
    |    return n + k + ro + b + c + global_limit;
    |}
    |
    |void refill(int *n);
    |
    |/* the guard holds when tested, then the value changes through a pointer to it */
    |void bad_guard_then_escape(int n)
    |{
    |    char buf[16];
    |    int *alias = &n;
    |    if (n < 0 || n >= 16) return;
    |    refill(alias);
    |    buf[n] = 0;
    |    note();
    |}
    |
    |/* the address is passed directly */
    |void bad_guard_then_direct_escape(int n)
    |{
    |    char buf[16];
    |    if (n < 0 || n >= 16) return;
    |    refill(&n);
    |    buf[n] = 0;
    |    note();
    |}
    |
    |/* written through the pointer after the guard */
    |void bad_guard_then_write_through(int n, int m)
    |{
    |    char buf[16];
    |    int *alias = &n;
    |    if (n < 0 || n >= 16) return;
    |    *alias = m;
    |    buf[n] = 0;
    |    note();
    |}
    |
    |/* the address left before the guard and nothing touches it after: still bounded */
    |void good_escape_before_guard(int n)
    |{
    |    char buf[16];
    |    refill(&n);
    |    if (n < 0 || n >= 16) return;
    |    buf[n] = 0;
    |    note();
    |}
    |
    |/* a compound assignment the schema spells <operators>.assignmentOr changes the value too */
    |void bad_guard_then_or_assign(int n, int bits)
    |{
    |    char buf[16];
    |    if (n < 0 || n >= 16) return;
    |    n |= bits;
    |    buf[n] = 0;
    |    note();
    |}
    |
    |#include "envbuf.h"
    |void save_env(env_t);
    |void header_array_typedef(void)
    |{
    |    env_t env2;
    |    save_env(env2);
    |}
    |
    |typedef int jbuf[8];
    |void save(int *);
    |void array_typedef(void)
    |{
    |    jbuf env;
    |    save(env);
    |}
    |
    |/* a name nothing declares (a macro the build would define) */
    |int undeclared_name(void)
    |{
    |    NOT_DECLARED_ANYWHERE += 1;
    |    return NOT_DECLARED_ANYWHERE;
    |}
    |
    |int flags_kind(int x)
    |{
    |    int flags = 0;
    |    flags |= x;
    |    return flags;
    |}
    |
    |/* a read-only parameter keeps its guard */
    |void good_read_only(int n)
    |{
    |    char buf[16];
    |    if (n < 0 || n >= 16) return;
    |    buf[n] = 0;
    |    note();
    |}
    |""".stripMargin,
    "refkinds.c"
  ).moreCode("typedef int env_t[4];\n", "envbuf.h")

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def kindsOf(method: String, name: String): Set[String] =
    val m = cpg.method.nameExact(method).l
    (m.local.nameExact(name).tag.l ++ m.parameter.nameExact(name).tag.l)
        .filter(_.name == Defines.ReferenceKindTag).map(_.value).toSet

  private def globalKinds(name: String): Set[String] =
      cpg.method.nameExact("<global>").local.nameExact(name).tag
          .nameExact(Defines.ReferenceKindTag).value.toSet

  private def boundFindings(method: String): List[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l)
          .filter(_.startsWith("MS-BOUND")).l

  "a variable" should {
      "be address-taken when its address leaves, and not modified by its own initializer" in {
          kindsOf("kinds", "n") shouldBe Set("address-taken")
      }
      "be modified when written after its declaration" in {
          kindsOf("kinds", "k") shouldBe Set("modified")
          kindsOf("kinds", "b") shouldBe Set("modified")
          kindsOf("kinds", "s") shouldBe Set("modified")
          globalKinds("global_count") shouldBe Set("modified")
          // `|=` is <operators>.assignmentOr in the schema
          kindsOf("flags_kind", "flags") shouldBe Set("modified")
      }
      "count an array passed out as address-taken and an element store as modified" in {
          kindsOf("kinds", "arr") shouldBe Set("modified", "address-taken")
          // an array behind a typedef decays the same way
          kindsOf("array_typedef", "env") shouldBe Set("address-taken")
          // also when a header the project does not parse defines the typedef (`jmp_buf`)
          kindsOf("header_array_typedef", "env2") shouldBe Set("address-taken")
      }
      "be read-only otherwise" in {
          kindsOf("kinds", "ro") shouldBe Set("read-only")
          kindsOf("kinds", "a") shouldBe Set("read-only")
          kindsOf("kinds", "c") shouldBe Set("read-only")
          kindsOf("kinds", "p") shouldBe Set("read-only")
          globalKinds("global_limit") shouldBe Set("read-only")
      }
  }

  "a guard on an address-taken variable" should {
      "not hold across a call that receives the address through a pointer" in {
          boundFindings("bad_guard_then_escape") should not be empty
      }
      "not hold across a call that receives the address directly" in {
          boundFindings("bad_guard_then_direct_escape") should not be empty
      }
      "not hold across a compound assignment of any spelling" in {
          boundFindings("bad_guard_then_or_assign") should not be empty
      }
      "not hold across a write through the pointer" in {
          boundFindings("bad_guard_then_write_through") should not be empty
      }
      "hold when the address left before the guard and nothing writes after it" in {
          boundFindings("good_escape_before_guard") shouldBe empty
      }
      "hold on a read-only parameter" in {
          boundFindings("good_read_only") shouldBe empty
      }
  }
end ReferenceKindTests

/** The object of a C++ member call is address-taken: the call receives `this`. */
class CppReferenceKindTests extends io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite(fileSuffix =
        io.appthreat.c2cpg.parser.FileDefaults.CPP_EXT
    ):
  "a C++ object" should {
      val cpg = code(
        """
          |struct Box { int value; int get() { return value; } };
          |void bump(int &n);
          |int use() {
          |  Box b; b.value = 1;
          |  int k = 0;
          |  bump(k);
          |  int plain = 2;
          |  Box *bp = &b;
          |  return b.get() + k + plain + bp->get();
          |}
          |""".stripMargin,
        "box.cpp"
      )
      def kinds(name: String): Set[String] =
          cpg.method.nameExact("use").local.nameExact(name).tag
              .nameExact(io.appthreat.x2cpg.Defines.ReferenceKindTag).value.toSet

      "be address-taken as the object of a member call" in {
          kinds("b") shouldBe Set("modified", "address-taken")
      }
      "be address-taken when bound to a non-const reference" in {
          kinds("k") shouldBe Set("address-taken")
      }
      "be read-only otherwise" in {
          kinds("plain") shouldBe Set("read-only")
          // a member call through a pointer receives the pointer's value, not its address
          kinds("bp") shouldBe Set("read-only")
      }
  }
end CppReferenceKindTests

/** C++ references and class assignment, and a guard across a call that binds the variable to a
  * non-const reference.
  */
class CppReferenceSemanticsTests extends io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite:
  private val cpg = code(
    """
      |struct Status { int code; Status &operator=(const Status &o) { code = o.code; return *this; } };
      |struct Options { int size; int limit() const { return size; } };
      |void refill(int &n);
      |void look(const int &n);
      |void note();
      |
      |int uses(const Options &options, Status s, Status t, int k) {
      |  s = t;
      |  look(k);
      |  return options.limit() + s.code;
      |}
      |
      |void bad_guard_then_ref(int n) {
      |  char buf[16];
      |  if (n < 0 || n >= 16) return;
      |  refill(n);
      |  buf[n] = 0;
      |  note();
      |}
      |
      |void good_guard_then_const_ref(int n) {
      |  char buf[16];
      |  if (n < 0 || n >= 16) return;
      |  look(n);
      |  buf[n] = 0;
      |  note();
      |}
      |""".stripMargin,
    "refs.cpp"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new IntegerWidthPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def kinds(method: String, name: String): Set[String] =
      cpg.method.nameExact(method).parameter.nameExact(name).tag
          .nameExact(Defines.ReferenceKindTag).value.toSet

  private def boundFindings(method: String): List[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l)
          .filter(_.startsWith("MS-BOUND")).l

  "a C++ variable" should {
      "take nothing when it is itself a reference" in {
          kinds("uses", "options") shouldBe Set("read-only")
      }
      "be modified by its class's assignment operator" in {
          kinds("uses", "s") should contain("modified")
      }
      "be address-taken when bound to a const reference" in {
          kinds("uses", "k") shouldBe Set("address-taken")
      }
  }

  "a guard" should {
      "not hold across a call that binds the variable to a non-const reference" in {
          boundFindings("bad_guard_then_ref") should not be empty
      }
      "hold across one that binds it to a const reference" in {
          boundFindings("good_guard_then_const_ref") shouldBe empty
      }
  }
end CppReferenceSemanticsTests
