package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** Taint through the Java constructs that hide a call behind a type, a body the source never names,
  * or an accumulator object.
  */
class TaintPrecisionTests extends JavaSrcCode2CpgFixture(withOssDataflow = true):

  private def taintFromParam(cpg: Cpg, method: String, param: String): Int =
    def source = cpg.method.name(method).parameter.name(param)
    cpg.call.name("println").argument(1).reachableBy(source).size

  "an enum constant with its own body" should {
      lazy val cpg = code("""
        |public class Main {
        |  enum Op {
        |    ECHO { String apply(String s) { System.out.println(s); return s; } },
        |    NOOP { String apply(String s) { return s; } };
        |    abstract String apply(String s);
        |  }
        |  void run(String tainted) { Op.ECHO.apply(tainted); }
        |}
        |""".stripMargin)

      "become a subclass of the enum" in {
          val echo = cpg.typeDecl.fullNameExact("Main$Op$ECHO").head
          echo.inheritsFromTypeFullName.l shouldBe List("Main$Op")
      }

      "declare the constant's override" in {
          cpg.method.fullNameExact(
            "Main$Op$ECHO.apply:java.lang.String(java.lang.String)"
          ).size shouldBe 1
      }

      "carry taint into the constant's body" in {
          taintFromParam(cpg, "run", "tainted") should be > 0
      }
  }

  "a generic supertype implemented at a concrete type" should {
      lazy val cpg = code("""
        |interface Box<T> { void put(T value); }
        |class StringBox implements Box<String> {
        |  public void put(String value) { System.out.println(value); }
        |}
        |public class Main { void run(Box<String> b, String tainted) { b.put(tainted); } }
        |""".stripMargin)

      "resolve the erased interface call to the concrete implementation" in {
          cpg.call.nameExact("put").callee(using NoResolve).fullName.l should contain(
            "StringBox.put:void(java.lang.String)"
          )
      }

      "carry taint into the implementation" in {
          taintFromParam(cpg, "run", "tainted") should be > 0
      }
  }

  "several same-arity overrides of a generic method" should {
      lazy val cpg = code("""
        |interface Box<T> { void put(T value); }
        |class Odd implements Box<String> {
        |  public void put(String value) {}
        |  public void put(Integer value) {}
        |}
        |public class Main { void run(Box<String> b, String tainted) { b.put(tainted); } }
        |""".stripMargin)

      "not guess between them" in {
          cpg.call.nameExact("put").callee(using NoResolve).fullName.l should contain only
              "Box.put:void(java.lang.Object)"
      }
  }

  "a string builder" should {
      lazy val cpg = code("""
        |public class Main {
        |  void run(String tainted) {
        |    StringBuilder sb = new StringBuilder();
        |    sb.append("prefix");
        |    sb.append(tainted);
        |    System.out.println(sb.toString());
        |  }
        |}
        |""".stripMargin)

      "carry an appended argument into the built string" in {
          taintFromParam(cpg, "run", "tainted") should be > 0
      }
  }

  "a lambda passed to a custom functional interface" should {
      lazy val cpg = code("""
        |interface Op { String apply(String s); }
        |public class Main {
        |  String call(Op op, String s) { return op.apply(s); }
        |  void run(String tainted) { System.out.println(call(x -> x, tainted)); }
        |}
        |""".stripMargin)

      "carry taint through the applied lambda" in {
          taintFromParam(cpg, "run", "tainted") should be > 0
      }
  }

  "a value parked in a static field" should {
      lazy val cpg = code("""
        |public class Main {
        |  static String held;
        |  static String untouched;
        |  static void store(String s) { held = s; }
        |  static void emit() { System.out.println(held); }
        |  static void emitUntouched() { System.out.println(untouched); }
        |  void go(String tainted) { store(tainted); emit(); }
        |}
        |""".stripMargin)

      "reach a read of it in another method" in {
          taintFromParam(cpg, "go", "tainted") should be > 0
      }

      "not reach a read of a static nobody writes" in {
          def source = cpg.method.name("go").parameter.name("tainted")
          cpg.method.name("emitUntouched").call.name("println").argument(1)
              .reachableBy(source).size shouldBe 0
      }
  }

  "an object whose constructor tainted one of its fields" should {
      lazy val cpg = code("""
        |public class Main {
        |  static class User {
        |    String name; String other;
        |    User(String n, String o) { this.name = n; this.other = o; }
        |    String name() { return this.name; }
        |    String other() { return this.other; }
        |  }
        |  void readTaintedField(String tainted) {
        |    User u = new User(tainted, "safe");
        |    System.out.println(u.name);
        |  }
        |  void readSafeField(String tainted) {
        |    User u = new User(tainted, "safe");
        |    System.out.println(u.other);
        |  }
        |  void readTaintedFieldViaGetter(String tainted) {
        |    User u = new User(tainted, "safe");
        |    System.out.println(u.name());
        |  }
        |  void readSafeFieldViaGetter(String tainted) {
        |    User u = new User(tainted, "safe");
        |    System.out.println(u.other());
        |  }
        |}
        |""".stripMargin)

      "reach a read of the field that was tainted" in {
          taintFromParam(cpg, "readTaintedField", "tainted") should be > 0
      }

      "not reach a read of a different field" in {
          def source = cpg.method.name("readSafeField").parameter.name("tainted")
          cpg.method.name("readSafeField").call.name("println").argument(1)
              .reachableBy(source).size shouldBe 0
      }

      "reach the tainted field through its getter" in {
          taintFromParam(cpg, "readTaintedFieldViaGetter", "tainted") should be > 0
      }

      "not reach a different field through its getter" in {
          def source = cpg.method.name("readSafeFieldViaGetter").parameter.name("tainted")
          cpg.method.name("readSafeFieldViaGetter").call.name("println").argument(1)
              .reachableBy(source).size shouldBe 0
      }
  }

  "an object passed on as a whole" should {
      lazy val cpg = code("""
        |public class Main {
        |  static class User {
        |    String name; String other;
        |    User(String n, String o) { this.name = n; this.other = o; }
        |  }
        |  static void consume(User u) { System.out.println(u.toString()); }
        |  void go(String tainted) { consume(new User(tainted, "safe")); }
        |}
        |""".stripMargin)

      "still carry taint, since no single field was singled out" in {
          taintFromParam(cpg, "go", "tainted") should be > 0
      }
  }

  "an interface default method" should {
      lazy val cpg = code("""
        |interface Greeter {
        |  String name();
        |  default void greet() { System.out.println(name()); }
        |}
        |class Impl implements Greeter {
        |  private final String n;
        |  Impl(String n) { this.n = n; }
        |  public String name() { return n; }
        |}
        |public class Main { void run(String tainted) { new Impl(tainted).greet(); } }
        |""".stripMargin)

      "resolve the self-call in the default body to the implementor" in {
          cpg.call.nameExact("name").callee(using NoResolve).fullName.l should contain(
            "Impl.name:java.lang.String()"
          )
      }

      "carry taint from the constructor into the default body" in {
          taintFromParam(cpg, "run", "tainted") should be > 0
      }
  }
end TaintPrecisionTests
