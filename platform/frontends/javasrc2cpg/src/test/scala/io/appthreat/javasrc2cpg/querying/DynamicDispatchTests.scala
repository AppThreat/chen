package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.shiftleft.semanticcpg.language.*

/** Call-graph precision for polymorphic (virtual / interface) dispatch. */
class DynamicDispatchTests extends JavaSrcCode2CpgFixture(withOssDataflow = true):

  "an interface call with two implementors" should {
      lazy val cpg = code("""
        |interface Greeter { String greet(String name); }
        |class Loud implements Greeter {
        |  public String greet(String name) { return name.toUpperCase(); }
        |}
        |class Quiet implements Greeter {
        |  public String greet(String name) { return name.toLowerCase(); }
        |}
        |public class Main {
        |  static void run(Greeter g, String s) { System.out.println(g.greet(s)); }
        |}
        |""".stripMargin)

      "be marked as dynamic dispatch" in {
          val call = cpg.call.nameExact("greet").head
          call.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH
      }

      "resolve to both implementations" in {
          val callees = cpg.call.nameExact("greet").callee(using NoResolve).fullName.l
          callees should contain("Loud.greet:java.lang.String(java.lang.String)")
          callees should contain("Quiet.greet:java.lang.String(java.lang.String)")
      }
  }

  "an abstract class hierarchy" should {
      lazy val cpg = code("""
        |abstract class Base { abstract void handle(String s); void run(String s) { handle(s); } }
        |class Impl extends Base { void handle(String s) { System.out.println(s); } }
        |""".stripMargin)

      "resolve the unqualified self-call to the subclass override" in {
          val callees = cpg.call.nameExact("handle").callee(using NoResolve).fullName.l
          callees should contain("Impl.handle:void(java.lang.String)")
      }
  }

  "an inherited, non-overridden method" should {
      lazy val cpg = code("""
        |class Base { void log(String s) { System.out.println(s); } }
        |class Child extends Base {}
        |public class Main { static void run(Child c) { c.log("x"); } }
        |""".stripMargin)

      "resolve to the base implementation" in {
          val callees = cpg.call.nameExact("log").callee(using NoResolve).fullName.l
          callees should contain("Base.log:void(java.lang.String)")
      }
  }

  "taint through an interface call" should {
      lazy val cpg = code("""
        |interface Sink { void accept(String s); }
        |class RealSink implements Sink {
        |  public void accept(String s) { System.out.println(s); }
        |}
        |public class Main {
        |  static void run(Sink s) { String tainted = "MALICIOUS"; s.accept(tainted); }
        |}
        |""".stripMargin)

      "reach the println inside the implementation" in {
          val source = cpg.literal.code("\"MALICIOUS\"")
          val sink   = cpg.call.name("println").argument(1)
          sink.reachableBy(source).size should be > 0
      }
  }

  "an inherited method whose name also appears as a package segment" should {
      lazy val cpg = code("""
        |package com.log;
        |class Base { void log(String s) { System.out.println(s); } }
        |class Child extends Base {}
        |public class Main { static void run(Child c) { c.log("x"); } }
        |""".stripMargin)

      "still resolve to the base implementation" in {
          val callees = cpg.call.nameExact("log").callee(using NoResolve).fullName.l
          callees should contain("com.log.Base.log:void(java.lang.String)")
      }
  }

  "an anonymous class implementing an interface" should {
      lazy val cpg = code("""
        |interface Sink { void accept(String s); }
        |public class Main {
        |  void run(String tainted) {
        |    Sink s = new Sink() { public void accept(String v) { System.out.println(v); } };
        |    s.accept(tainted);
        |  }
        |}
        |""".stripMargin)

      "carry taint into the anonymous body" in {
          def source = cpg.method.name("run").parameter.name("tainted")
          cpg.call.name("println").argument(1).reachableBy(source).size should be > 0
      }
  }

  "an anonymous class in a field initializer" should {
      lazy val cpg = code("""
        |interface Sink { void accept(String s); }
        |public class Main {
        |  private final Sink sink = new Sink() { public void accept(String v) { System.out.println(v); } };
        |  void run(String tainted) { sink.accept(tainted); }
        |}
        |""".stripMargin)

      "become a type of its own under the enclosing class" in {
          val anon = cpg.typeDecl.fullNameExact("Main$1").head
          anon.inheritsFromTypeFullName.l shouldBe List("Sink")
          anon.astParentFullName shouldBe "Main"
      }

      "carry taint into the anonymous body" in {
          def source = cpg.method.name("run").parameter.name("tainted")
          cpg.call.name("println").argument(1).reachableBy(source).size should be > 0
      }
  }

  "nested anonymous classes" should {
      lazy val cpg = code("""
        |interface Outer { void run(String s); }
        |interface Inner { void go(String s); }
        |public class Main {
        |  void build(String tainted) {
        |    Outer o = new Outer() {
        |      public void run(String a) {
        |        Inner i = new Inner() { public void go(String b) { System.out.println(b); } };
        |        i.go(a);
        |      }
        |    };
        |    o.run(tainted);
        |  }
        |}
        |""".stripMargin)

      "nest the inner declaration under the outer one" in {
          cpg.typeDecl.fullNameExact("Main$1$1").head.astParentFullName shouldBe "Main$1"
      }

      "carry taint through both levels" in {
          def source = cpg.method.name("build").parameter.name("tainted")
          cpg.call.name("println").argument(1).reachableBy(source).size should be > 0
      }
  }

  "a method reference target" should {
      lazy val cpg = code("""
        |import java.util.List;
        |public class Main {
        |  void handle(String s) { System.out.println(s); }
        |  void run(List<String> xs) { xs.forEach(this::handle); }
        |}
        |""".stripMargin)

      "bind the method ref to the declared method" in {
          cpg.methodRef.methodFullNameExact("Main.handle:void(java.lang.String)").size shouldBe 1
      }

      "carry taint from the iterated collection into the referenced method" in {
          def source = cpg.method.name("run").parameter.name("xs")
          cpg.call.name("println").argument(1).reachableBy(source).size should be > 0
      }
  }
end DynamicDispatchTests
