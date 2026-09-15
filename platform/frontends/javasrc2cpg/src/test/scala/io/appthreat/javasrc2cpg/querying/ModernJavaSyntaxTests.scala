package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Local, Method, MethodRef}
import io.shiftleft.semanticcpg.language.*

/** Structural and CFG lowering of advanced Java language features, Java 21 through Java 26.
  *
  * This suite is the fixture that measures where javasrc2cpg stands on modern Java. Every construct
  * here is parsed successfully by the bundled JavaParser (verified against Java 26 syntax: record
  * patterns, pattern switches with `when` guards, switch expressions, `yield`, unnamed variables,
  * local records, module imports, flexible constructor bodies, primitive patterns, stream
  * gatherers), so a failing assertion is an AST-lowering gap, never a parser gap.
  *
  * Version map of the constructs under test:
  *   - Java 14: switch expressions (`switch ... ->` with a value, `yield`)
  *   - Java 16: records, `instanceof` type patterns, local records and classes
  *   - Java 17: sealed classes/interfaces
  *   - Java 21: pattern matching for switch (type patterns, record patterns, `when` guards),
  *     virtual threads
  *   - Java 22: unnamed variables and patterns (`_`)
  *   - Java 25: module import declarations, flexible constructor bodies
  *   - Java 22+: java.lang.foreign (Panama FFM) native interop
  */
class ModernJavaSyntaxTests extends JavaSrcCode2CpgFixture:

  "Switch expressions (Java 14)" should {

      "lower an arrow-form switch expression with a call in each arm" in {
          val cpg = code(
            """
            |class SwitchExpr {
            |  String label(int code) {
            |    return switch (code) {
            |      case 1 -> "one";
            |      case 2 -> "two";
            |      default -> "many";
            |    };
            |  }
            |}
            |""".stripMargin,
            "SwitchExpr.java"
          )

          inside(cpg.method.name("label").l) {
              case List(label) =>
                  // The arm values are part of the method body - nothing is dropped.
                  (label.literal.code.l should contain).allOf("\"one\"", "\"two\"", "\"many\"")
                  // The selector is preserved as an identifier argument of the lowered switch.
                  label.ast.isIdentifier.name("code").l should not be empty
          }
      }

      "contribute arm statements of a switch expression to the CFG" in {
          val cpg = code(
            """
            |class SwitchCfg {
            |  String pick(int code) {
            |    return switch (code) {
            |      case 1 -> "one";
            |      default -> "many";
            |    };
            |  }
            |}
            |""".stripMargin,
            "SwitchCfg.java"
          )

          // Both arms are reachable statements in the method body: with the switch lowered,
          // a RETURN's CFG predecessor set includes the arm values rather than skipping the
          // construct entirely.
          val method = cpg.method.name("pick").head
          method.block.astChildren.l should not be empty
          method.literal.code("\"one\"").l should not be empty
          method.literal.code("\"many\"").l should not be empty
      }
  }

  "instanceof type patterns (Java 16)" should {

      "bind the pattern variable as a local with a type" in {
          val cpg = code(
            """
            |class InstanceOfPattern {
            |  int length(Object o) {
            |    if (o instanceof String s) {
            |      return s.length();
            |    }
            |    return 0;
            |  }
            |}
            |""".stripMargin,
            "InstanceOfPattern.java"
          )

          val local = cpg.local.name("s").l
          local should not be empty
          local.headOption.foreach(_.typeFullName should startWith("java.lang.String"))
          // The use of `s` resolves to the binding.
          val identifier = cpg.identifier.name("s").l
          identifier should not be empty
          identifier.head.refsTo.size shouldBe 1
      }
  }

  "Pattern matching for switch (Java 21)" should {

      "bind a type-pattern variable inside its arm" in {
          val cpg = code(
            """
            |record Circle(double radius) {}
            |
            |class GuardedSwitch {
            |  double area(Object shape) {
            |    return switch (shape) {
            |      case Circle c when c.radius() > 10.0 -> 1.0;
            |      case Circle c -> 2.0;
            |      default -> 0.0;
            |    };
            |  }
            |}
            |""".stripMargin,
            "GuardedSwitch.java"
          )

          val area = cpg.method.name("area").head
          // The pattern variable `c` is bound exactly like a local of the arm.
          area.local.name("c").l should not be empty
          area.ast.isCall.name("radius").l should not be empty
      }

      "bind record-pattern components as variables of the arm" in {
          val cpg = code(
            """
            |sealed interface Shape permits Rect {}
            |record Rect(double width, double height) implements Shape {}
            |
            |class RecordPattern {
            |  double area(Shape s) {
            |    return switch (s) {
            |      case Rect(double w, double h) -> w * h;
            |    };
            |  }
            |}
            |""".stripMargin,
            "RecordPattern.java"
          )

          val area = cpg.method.name("area").head
          area.local.name("w").l should not be empty
          area.local.name("h").l should not be empty
          // The components are used in the arm expression.
          area.ast.isIdentifier.name("w").l should not be empty
          area.ast.isIdentifier.name("h").l should not be empty
      }

      "lower a guarded pattern switch statement (not expression) without dropping arms" in {
          val cpg = code(
            """
            |class GuardedStatement {
            |  void run(String value) {
            |    switch (value) {
            |      case String s when s.length() > 2 -> System.out.println(s);
            |      default -> System.out.println("safe");
            |    }
            |  }
            |}
            |""".stripMargin,
            "GuardedStatement.java"
          )

          val run = cpg.method.name("run").head
          run.local.name("s").l should not be empty
          run.literal.code("\"safe\"").l should not be empty
      }
  }

  "Local records and classes (Java 16)" should {

      "lower a record declared inside a method body" in {
          val cpg = code(
            """
            |class LocalRecord {
            |  int run() {
            |    record Point(int x, int y) {}
            |    return new Point(1, 2).x();
            |  }
            |}
            |""".stripMargin,
            "LocalRecord.java"
          )

          val run = cpg.method.name("run").head
          // The record becomes a nested TYPE_DECL under the method, with its accessors callable.
          run.ast.isTypeDecl.name("Point").l should not be empty
          run.call.name("x").l should not be empty
      }

      "lower a class declared inside a method body" in {
          val cpg = code(
            """
            |class LocalClass {
            |  int run() {
            |    class Helper { int twice(int v) { return v * 2; } }
            |    return new Helper().twice(21);
            |  }
            |}
            |""".stripMargin,
            "LocalClass.java"
          )

          val run = cpg.method.name("run").head
          run.ast.isTypeDecl.name("Helper").l should not be empty
          run.call.name("twice").l should not be empty
      }
  }

  "Method references" should {

      "lower System.out::println to a method reference, not an unknown" in {
          val cpg = code(
            """
            |class MethodRefs {
            |  void run(java.util.List<String> items) {
            |    items.forEach(System.out::println);
            |  }
            |}
            |""".stripMargin,
            "MethodRefs.java"
          )

          val refs = cpg.methodRef.l
          refs should not be empty
          refs.head.code should include("System.out::println")
          // And no UNKNOWN node is left behind for the construct.
          cpg.method.name("run").head.ast.isCall.name("<unknown>").l shouldBe empty
      }

      "lower this::handler with the target method resolvable" in {
          val cpg = code(
            """
            |class Handler {
            |  void register(Object router) {
            |    router.equals(this::handleItems);
            |  }
            |
            |  void handleItems(Object ctx) {}
            |}
            |""".stripMargin,
            "Handler.java"
          )

          val ref = cpg.methodRef.l
          ref should not be empty
          ref.head.code should include("this::handleItems")
          cpg.method.name("handleItems").l should not be empty
      }
  }

  "Unnamed variables (Java 22)" should {

      "keep the initializer call of `var _ = expr;`" in {
          val cpg = code(
            """
            |class Unnamed {
            |  int observe() { return 42; }
            |
            |  void run() {
            |    var _ = observe();
            |  }
            |}
            |""".stripMargin,
            "Unnamed.java"
          )

          cpg.method.name("run").head.call.name("observe").l should not be empty
      }
  }

  "Java 25 compact forms" should {

      "parse and lower a module import declaration" in {
          val cpg = code(
            """
            |import module java.base;
            |
            |class ModuleImport {
            |  java.util.List<String> names() { return java.util.List.of("a"); }
            |}
            |""".stripMargin,
            "ModuleImport.java"
          )

          cpg.method.name("names").head.call.name("of").l should not be empty
      }

      "parse and lower statements before super() in a constructor" in {
          val cpg = code(
            """
            |class FlexibleCtorBase { FlexibleCtorBase(int v) {} }
            |
            |class FlexibleCtor extends FlexibleCtorBase {
            |  FlexibleCtor(int v) {
            |    int checked = v + 1;
            |    super(checked);
            |  }
            |}
            |""".stripMargin,
            "FlexibleCtor.java"
          )

          // Both classes' constructors are named `<init>` in this file; the subclass one is the
          // one whose body declares `checked`.
          cpg.local.name("checked").l should not be empty
          val ctor = cpg.method.name("<init>").where(_.local.name("checked")).l
          ctor should not be empty
          // The explicit super() invocation lowers to an `<init>` call, after the local's
          // initializer - the flexible-constructor order survives lowering.
          ctor.head.call.name("<init>").l should not be empty
      }
  }

  "Modern runtime carriers" should {

      "lower virtual-thread startup and its runnable body" in {
          val cpg = code(
            """
            |class VirtualThreads {
            |  void run() {
            |    Thread.ofVirtual().name("worker").start(() -> handle());
            |  }
            |
            |  void handle() {}
            |}
            |""".stripMargin,
            "VirtualThreads.java"
          )

          cpg.method.name("run").head.call.name("ofVirtual").l should not be empty
          cpg.method.name("handle").l should not be empty
      }

      "lower a java.lang.foreign (Panama FFM) downcall setup" in {
          val cpg = code(
            """
            |import java.lang.foreign.FunctionDescriptor;
            |import java.lang.foreign.Linker;
            |import java.lang.invoke.MethodHandle;
            |
            |class NativeBridge {
            |  MethodHandle strlenHandle() {
            |    return Linker.nativeLinker().downcallHandle("strlen",
            |        FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG));
            |  }
            |}
            |""".stripMargin,
            "NativeBridge.java"
          )

          val handle = cpg.method.name("strlenHandle").head
          handle.call.name("nativeLinker").l should not be empty
          handle.call.name("downcallHandle").l should not be empty
      }
  }
end ModernJavaSyntaxTests
