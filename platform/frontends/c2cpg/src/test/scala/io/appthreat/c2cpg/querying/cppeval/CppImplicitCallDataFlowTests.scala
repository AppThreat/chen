package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language.*

/** Data flow through the calls C++ makes without spelling them: the frontend links them to their
  * METHODs, so a flow reaches a template's, a lambda's and a constructor's body, and an overloaded
  * operator still carries its operands to its result.
  */
class CppImplicitCallDataFlowTests extends CppDataFlowCodeToCpgSuite:

  private val cpg = code("""
      |char *source();
      |void sink(const char *s);
      |void sinkInt(int n);
      |
      |template <typename T> T identity(T v) { return v; }
      |
      |struct Text {
      |  const char *s;
      |  Text() : s(0) {}
      |  explicit Text(const char *p) { s = p; sink(p); }
      |  Text operator+(const Text &o) const { return Text(o.s); }
      |  Text &operator=(const Text &o) { s = o.s; return *this; }
      |};
      |
      |void throughTemplate() {
      |  char *data = source();
      |  sink(identity(data));
      |}
      |
      |void throughLambda() {
      |  auto relay = [](const char *q) { return q; };
      |  sink(relay(source()));
      |}
      |
      |void throughOperator() {
      |  Text a(source());
      |  Text b;
      |  Text c = a + b;
      |  Text d;
      |  d = c;
      |  sink(d.s);
      |}
      |
      |void throughFunctionalCast() {
      |  Text t = Text(source());
      |  sink(t.s);
      |}
      |
      |void overwritten() {
      |  Text d;
      |  d = Text(source());
      |  d = Text("constant");
      |  sink(d.s);
      |}
      |""".stripMargin)

  /** The C summaries, as atom queries a C/C++ graph with them. */
  private lazy val cContext: EngineContext =
    val semantics = DefaultSemantics.cSemantics()
    semantics.loadRegexSemantics(cpg)
    EngineContext(semantics)

  private def sinkArgsIn(method: String) =
      cpg.method.nameExact(method).call.nameExact("sink").argument

  private def sources = cpg.call.nameExact("source")

  private def methodsOn(flows: List[Path]): Set[String] =
      flows.flatMap(_.elements.collect { case n: CfgNode => n.method.name }).toSet

  "a template instance call" should {
      "carry the argument through the generic definition's body" in {
          val flows = sinkArgsIn("throughTemplate").reachableByFlows(sources)(using cContext).l
          flows should not be empty
          methodsOn(flows) should contain("identity")
      }
  }

  "a call through a lambda's closure" should {
      "carry the argument through the lambda's body" in {
          val flows = sinkArgsIn("throughLambda").reachableByFlows(sources)(using cContext).l
          flows should not be empty
          methodsOn(flows).exists(_.startsWith("anonymous_lambda")) shouldBe true
      }
  }

  "a constructor" should {
      "reach a sink inside its body from the constructor argument" in {
          val inCtor =
              cpg.method.fullNameExact("Text.Text:void(char*)").call.nameExact("sink").argument
          inCtor.reachableByFlows(sources)(using cContext).l.flatMap(p => methodsOn(List(p)))
              .toSet should contain(
            "throughOperator"
          )
      }

      "build its value from its arguments" in {
          sinkArgsIn("throughFunctionalCast").reachableByFlows(sources)(using cContext).l should not be empty
      }
  }

  "an assignment operator" should {
      "replace what its left operand held" in {
          sinkArgsIn("overwritten").reachableByFlows(sources)(using cContext).l shouldBe empty
      }
  }

  "an overloaded operator" should {
      "carry its operands to its result, and an assignment into its left operand" in {
          sinkArgsIn("throughOperator").reachableByFlows(cpg.identifier.nameExact("a"))(using
          cContext).l should not be empty
          sinkArgsIn("throughOperator").reachableByFlows(cpg.identifier.nameExact("c"))(using
          cContext).l should not be empty
      }
  }
end CppImplicitCallDataFlowTests
