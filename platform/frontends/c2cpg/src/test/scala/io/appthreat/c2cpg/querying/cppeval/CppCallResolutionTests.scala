package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** Confidence coverage for callee resolution (`Call.methodFullName`) across the common C++ call
  * forms: free functions, namespaced functions, instance/pointer member calls, static and virtual
  * member calls, type-distinguished overloads, explicit/deduced template instantiations and
  * recursion. These are the resolutions a reachability/call-graph analysis depends on.
  */
class CppCallResolutionTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private implicit val resolver: NoResolve.type = NoResolve

  private val cpg = code("""
      |namespace ns {
      |    int freeFn(int x) { return x; }
      |    struct S {
      |        int mem(int x) { return x; }
      |        static int stat(int x) { return x; }
      |        virtual int vf(int x) { return x; }
      |    };
      |}
      |int freeTop(int x) { return x; }
      |int overloaded(int x) { return x; }
      |double overloaded(double x) { return x; }
      |template <typename T> T tmax(T a, T b) { return a > b ? a : b; }
      |int recurse(int n) { return n <= 0 ? 0 : recurse(n - 1); }
      |int caller() {
      |    int r = 0;
      |    r += freeTop(1);
      |    r += ns::freeFn(2);
      |    ns::S s;
      |    r += s.mem(3);
      |    ns::S* p = &s;
      |    r += p->mem(4);
      |    r += ns::S::stat(5);
      |    r += p->vf(6);
      |    r += overloaded(7);
      |    r += (int)overloaded(7.5);
      |    r += tmax<int>(8, 9);
      |    r += tmax(10, 11);
      |    r += recurse(3);
      |    return r;
      |}
      |""".stripMargin)

  private def mfnOf(callCode: String): String =
      cpg.method.nameExact("caller").call.codeExact(callCode).methodFullName.head

  "callee resolution" should {
      "resolve a top-level free function call" in {
          mfnOf("freeTop(1)") shouldBe "freeTop:int(int)"
      }
      "resolve a namespaced free function call" in {
          mfnOf("ns::freeFn(2)") shouldBe "ns.freeFn:int(int)"
      }
      "resolve an instance member call" in {
          mfnOf("s.mem(3)") shouldBe "ns.S.mem:int(int)"
      }
      "resolve a member call through a pointer" in {
          mfnOf("p->mem(4)") shouldBe "ns.S.mem:int(int)"
      }
      "resolve a static member call" in {
          mfnOf("ns::S::stat(5)") shouldBe "ns.S.stat:int(int)"
      }
      "resolve a virtual member call to the declared method" in {
          mfnOf("p->vf(6)") shouldBe "ns.S.vf:int(int)"
      }
      "distinguish overloads by argument type" in {
          mfnOf("overloaded(7)") shouldBe "overloaded:int(int)"
          mfnOf("overloaded(7.5)") shouldBe "overloaded:double(double)"
      }
      "resolve an explicit template instantiation" in {
          mfnOf("tmax<int>(8, 9)") shouldBe "tmax:int(int,int)"
      }
      "resolve a deduced template instantiation" in {
          mfnOf("tmax(10, 11)") shouldBe "tmax:int(int,int)"
      }
      "resolve a recursive self-call" in {
          mfnOf("recurse(3)") shouldBe "recurse:int(int)"
      }
  }

  "the call graph" should {
      "link caller to every resolved callee" in {
          val callees = cpg.method.nameExact("caller").callee.fullName.toSetMutable
          (callees should contain).allOf(
            "freeTop:int(int)",
            "ns.freeFn:int(int)",
            "ns.S.mem:int(int)",
            "ns.S.stat:int(int)",
            "ns.S.vf:int(int)",
            "recurse:int(int)"
          )
      }
      "make the recursive method its own caller and callee" in {
          cpg.method.nameExact("recurse").callee.fullName.l should contain("recurse:int(int)")
          (cpg.method.nameExact("recurse").caller.name.toSetMutable should contain).allOf(
            "caller",
            "recurse"
          )
      }
  }
end CppCallResolutionTests
