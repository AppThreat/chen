package io.appthreat.c2cpg.dataflow

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*

/** Values a C++ object carries between its member functions, and virtual calls on an object whose
  * class the code shows.
  */
class CppObjectFlowTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
      |char *getenv(const char *name);
      |int system(const char *command);
      |class Holder {
      | public:
      |  Holder(char *copy) { data = copy; }
      |  ~Holder() { system(data); }
      |  void run() { system(other); }
      | private:
      |  char *data;
      |  char *other;
      |};
      |void stack_object() {
      |  Holder h(getenv("HELD"));
      |}
      |class Base {
      | public:
      |  virtual void action(char *d) const = 0;
      |  virtual ~Base() {}
      |};
      |class Bad : public Base {
      | public:
      |  void action(char *d) const override { system(d); }
      |};
      |class Good : public Base {
      | public:
      |  void action(char *d) const override { (void)d; }
      |};
      |void by_reference() {
      |  const Base &b = Bad();
      |  b.action(getenv("REF"));
      |}
      |void by_pointer() {
      |  Base *b = new Good;
      |  b->action(getenv("PTR"));
      |  delete b;
      |}
      |void unknown(Base *b) { b->action(getenv("ANY")); }
      |""".stripMargin,
    "objects.cpp"
  )

  "a value a constructor stores in a member" should {
      "reach the member's reads in the class's other member functions" in {
          cpg.method.nameExact("~Holder").call.name("system").argument(1)
              .reachableByFlows(cpg.call.name("getenv").where(_.argument.code("\"HELD\""))).l should
              not be empty
      }
      "not reach another member" in {
          cpg.method.nameExact("run").call.name("system").argument(1)
              .reachableByFlows(cpg.call.name("getenv")).l shouldBe empty
      }
  }

  "a virtual call on an object created as one class" should {
      def callees(method: String): List[String] =
          cpg.method.nameExact(method).call.nameExact("action").flatMap(
            _._callOut.collectAll[Method].filterNot(_.isExternal).fullName
          ).l.sorted

      "reach that class's override alone" in {
          callees("by_reference").filterNot(_.startsWith("Base.")) shouldBe List(
            "Bad.action:void(char*)"
          )
          callees("by_pointer").filterNot(_.startsWith("Base.")) shouldBe List(
            "Good.action:void(char*)"
          )
      }
      "keep every override when the class is not known" in {
          callees("unknown").filterNot(_.startsWith("Base.")) shouldBe List(
            "Bad.action:void(char*)",
            "Good.action:void(char*)"
          )
      }
  }
end CppObjectFlowTests
