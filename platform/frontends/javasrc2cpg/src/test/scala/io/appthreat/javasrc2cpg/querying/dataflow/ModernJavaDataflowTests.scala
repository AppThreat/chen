package io.appthreat.javasrc2cpg.querying.dataflow

import io.appthreat.javasrc2cpg.JavaSrc2CpgTestContext
import io.appthreat.javasrc2cpg.testfixtures.JavaDataflowFixture
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Expression, Literal}
import io.shiftleft.semanticcpg.language.*

/** Dataflow through advanced Java language features, Java 21 through Java 26.
  *
  * The companion suite [[io.appthreat.javasrc2cpg.querying.ModernJavaSyntaxTests]] pins the
  * structural lowering; this one pins that the Java Language Specification's value movement
  * survives the lowering:
  *
  *   - a switch expression's value is the value of the matched arm, so taint in any arm value flows
  *     to the expression's result (`JLS 14.11.2`); the selector's content never does - it only
  *     selects - which is why the selector has no flow test below;
  *   - a pattern variable is definitely assigned inside its arm (`JLS 6.3`), so taint on the
  *     tested/matched value flows to the pattern binding and through it to uses in the arm;
  *   - a record pattern's components are aliases of the matched record's components, so a tainted
  *     value taints the components bound by the pattern.
  *
  * Every fixture keeps the `"MALICIOUS"` source literal inside the method under test so the source
  * is a node of the method's own body, and funnels the flow into `sink(...)` so one number pins the
  * whole path.
  */
class ModernJavaDataflowTests extends JavaDataflowFixture:

  /** The number of taint paths from a PARAMETER (a method's web-facing boundary in practice) to the
    * method's `sink` calls. This is the shape the framework taggers produce: a servlet or
    * controller parameter is the source, and the flow must survive switch expressions and pattern
    * bindings on the way to the sink.
    */
  private def paramFlowCount(code: String, methodName: String, paramName: String): Int =
    val cpg      = JavaSrc2CpgTestContext.buildCpgWithDataflow(code)
    val source   = cpg.method.name(methodName).head.parameter.name(paramName).l
    val sinkCall = cpg.method.name(methodName).head.call.name("sink").l
    source should not be empty
    sinkCall should not be empty
    val sinks: Iterator[Expression] = sinkCall.iterator.flatMap(_.argument(1).ast.isExpression)
    sinks.reachableBy(source).distinct.size

  /** The number of taint paths from the `"MALICIOUS"` literal to the method's `sink` calls. */
  private def flowCount(code: String, methodName: String): Int =
    val cpg      = JavaSrc2CpgTestContext.buildCpgWithDataflow(code)
    val source   = cpg.method.name(methodName).head.literal.code("\"MALICIOUS\"").l
    val sinkCall = cpg.method.name(methodName).head.call.name("sink").l
    source should not be empty
    sinkCall should not be empty
    val sinks: Iterator[Expression] = sinkCall.iterator.flatMap(_.argument(1).ast.isExpression)
    sinks.reachableBy(source).distinct.size

  behavior of "Dataflow through modern Java constructs"

  it should "flow through an arrow-form switch expression from a tainted arm" in {
      flowCount(
        """
          |class Flows {
          |  void sink(String s) {}
          |
          |  void switchExprArm(int code) {
          |    String tainted = "MALICIOUS";
          |    String value = switch (code) {
          |      case 1 -> tainted;
          |      default -> "safe";
          |    };
          |    sink(value);
          |  }
          |}
          |""".stripMargin,
        "switchExprArm"
      ) shouldBe 1
  }

  it should "flow through a colon-form switch expression that yields" in {
      flowCount(
        """
          |class Flows {
          |  void sink(String s) {}
          |
          |  void yieldArm(int code) {
          |    String tainted = "MALICIOUS";
          |    String value = switch (code) {
          |      case 1: yield tainted;
          |      default: yield "safe";
          |    };
          |    sink(value);
          |  }
          |}
          |""".stripMargin,
        "yieldArm"
      ) shouldBe 1
  }

  it should "flow through a block arm that yields after side effects" in {
      flowCount(
        """
          |class Flows {
          |  void sink(String s) {}
          |  void audit() {}
          |
          |  void blockArm(int code) {
          |    String tainted = "MALICIOUS";
          |    String value = switch (code) {
          |      case 1 -> {
          |        audit();
          |        yield tainted;
          |      }
          |      default -> "safe";
          |    };
          |    sink(value);
          |  }
          |}
          |""".stripMargin,
        "blockArm"
      ) shouldBe 1
  }

  it should "flow through a switch expression nested in another arm value" in {
      flowCount(
        """
          |class Flows {
          |  void sink(String s) {}
          |
          |  void nestedSwitch(int code, int other) {
          |    String tainted = "MALICIOUS";
          |    String inner = switch (other) {
          |      case 0 -> tainted;
          |      default -> "i";
          |    };
          |    String value = switch (code) {
          |      case 1 -> inner;
          |      default -> "safe";
          |    };
          |    sink(value);
          |  }
          |}
          |""".stripMargin,
        "nestedSwitch"
      ) shouldBe 1
  }

  it should "flow through an instanceof pattern binding" in {
      flowCount(
        """
          |class Flows {
          |  void sink(String s) {}
          |
          |  void instanceOfPattern() {
          |    Object o = "MALICIOUS";
          |    if (o instanceof String s) {
          |      sink(s);
          |    }
          |  }
          |}
          |""".stripMargin,
        "instanceOfPattern"
      ) shouldBe 1
  }

  it should "flow through a guarded pattern arm binding" in {
      flowCount(
        """
          |class Flows {
          |  void sink(String s) {}
          |
          |  void guardedPattern() {
          |    Object value = "MALICIOUS";
          |    switch (value) {
          |      case String s when s.length() > 2 -> sink(s);
          |      default -> sink("safe");
          |    }
          |  }
          |}
          |""".stripMargin,
        "guardedPattern"
      ) shouldBe 1
  }

  it should "carry taint through a plain (re)assignment of a switch expression" in {
      flowCount(
        """
          |class Flows {
          |  void sink(String s) {}
          |
          |  void assignSwitch(int code) {
          |    String tainted = "MALICIOUS";
          |    String value = "safe";
          |    value = switch (code) {
          |      case 1 -> tainted;
          |      default -> value;
          |    };
          |    sink(value);
          |  }
          |}
          |""".stripMargin,
        "assignSwitch"
      ) shouldBe 1
  }

  it should "carry a parameter through a switch expression with pattern arms to a sink" in {
      paramFlowCount(
        """
          |class Flows {
          |  void sink(String s) {}
          |
          |  void switchPatternParam(String kind) {
          |    String command = switch (kind) {
          |      case "greet" -> "echo hello";
          |      case String k when k.length() > 3 -> "echo " + k;
          |      default -> "echo noop";
          |    };
          |    sink(command);
          |  }
          |}
          |""".stripMargin,
        "switchPatternParam",
        "kind"
      ) shouldBe 1
  }

  it should "flow through a return-position switch expression from a tainted arm" in {
      // Cross-method: the literal is defined in `yieldReturn` and consumed by `caller`'s sink,
      // so the assertion runs over the whole graph rather than one method.
      val cpg = JavaSrc2CpgTestContext.buildCpgWithDataflow(
        """
          |class Flows {
          |  void sink(String s) {}
          |
          |  String yieldReturn(int code) {
          |    String tainted = "MALICIOUS";
          |    return switch (code) {
          |      case 1 -> tainted;
          |      default -> "safe";
          |    };
          |  }
          |
          |  void caller() {
          |    sink(yieldReturn(1));
          |  }
          |}
          |""".stripMargin
      )
      val source = cpg.method.name("yieldReturn").head.literal.code("\"MALICIOUS\"").l
      val sinks: Iterator[Expression] =
          cpg.method.name("caller").head.call.name("sink").argument(1).ast.isExpression
      source should not be empty
      sinks.reachableBy(source).distinct.size shouldBe 1
  }

  it should "flow through record-pattern component bindings" in {
      flowCount(
        """
          |record Box(String content) {}
          |
          |class Flows {
          |  void sink(String s) {}
          |
          |  void recordPattern() {
          |    Object o = "MALICIOUS";
          |    if (o instanceof Box(String c)) {
          |      sink(c);
          |    }
          |  }
          |}
          |""".stripMargin,
        "recordPattern"
      ) shouldBe 1
  }
end ModernJavaDataflowTests
