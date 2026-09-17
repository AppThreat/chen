package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*

/** Call-graph and taint behaviour of reflective dispatch, lowered by
  * `io.appthreat.javasrc2cpg.passes.ReflectionLoweringPass`.
  */
class ReflectionTests extends JavaSrcCode2CpgFixture(withOssDataflow = true):

  "a Class.forName + getMethod + invoke chain" should {
      lazy val cpg = code("""
        |import java.lang.reflect.Method;
        |public class Main {
        |  public void sink(String s) { System.out.println(s); }
        |  void run(String tainted) throws Exception {
        |    Class<?> c = Class.forName("Main");
        |    Object o = c.newInstance();
        |    Method m = c.getMethod("sink", String.class);
        |    m.invoke(o, tainted);
        |  }
        |}
        |""".stripMargin)

      "rewrite the invocation onto the resolved target" in {
          val call = cpg.method.name("run").ast.isCall.code("m.invoke.*").head
          call.name shouldBe "sink"
          call.methodFullName shouldBe "Main.sink:void(java.lang.String)"
          // The original source text is preserved so findings still point at what was written.
          call.code shouldBe "m.invoke(o, tainted)"
      }

      "line the reflective arguments up with the target's parameters" in {
          val call = cpg.method.name("run").ast.isCall.code("m.invoke.*").head
          call.argument.l.map(a => a.argumentIndex -> a.code) shouldBe List(
            0 -> "o",
            1 -> "tainted"
          )
          call.receiver.code.l shouldBe List("o")
      }

      "link the call graph through to the target" in {
          cpg.method.name("run").ast.isCall.code("m.invoke.*").callee(using NoResolve).fullName
              .l should contain("Main.sink:void(java.lang.String)")
      }

      "carry taint into the reflectively invoked body" in {
          def source = cpg.method.name("run").parameter.name("tainted")
          cpg.call.name("println").argument(1).reachableBy(source).size should be > 0
      }

      "resolve Class.newInstance to the constructor" in {
          cpg.method.name("run").ast.isCall.code("c.newInstance.*").callee(using NoResolve).fullName
              .l should contain("Main.<init>:void()")
      }
  }

  "a Constructor.newInstance with arguments" should {
      lazy val cpg = code("""
        |package com.example;
        |import java.lang.reflect.Constructor;
        |public class Main {
        |  // Nested, so the class literal's source text is not the full name the graph indexes by.
        |  public static class Holder { Holder(String v) { System.out.println(v); } }
        |  void run(String tainted) throws Exception {
        |    Constructor<?> ctor = Holder.class.getConstructor(String.class);
        |    Object o = ctor.newInstance(tainted);
        |  }
        |}
        |""".stripMargin)

      "carry taint into the constructor body" in {
          def source = cpg.method.name("run").parameter.name("tainted")
          cpg.call.name("println").argument(1).reachableBy(source).size should be > 0
      }
  }

  "an ambiguous or non-constant reflective target" should {
      lazy val cpg = code("""
        |import java.lang.reflect.Method;
        |public class Main {
        |  public void sink(String s) {}
        |  public void sink(int i) {}
        |  void overloaded(String tainted) throws Exception {
        |    Class<?> c = Class.forName("Main");
        |    Method m = c.getMethod("sink", String.class);
        |    m.invoke(this, tainted);
        |  }
        |  void dynamicName(String name, String tainted) throws Exception {
        |    Class<?> c = Class.forName("Main");
        |    Method m = c.getMethod(name, String.class);
        |    m.invoke(this, tainted);
        |  }
        |}
        |""".stripMargin)

      "leave an overloaded name alone rather than pick an arbitrary overload" in {
          cpg.method.name("overloaded").ast.isCall.code("m.invoke.*").head.name shouldBe "invoke"
      }

      "leave a non-literal method name alone" in {
          cpg.method.name("dynamicName").ast.isCall.code("m.invoke.*").head.name shouldBe "invoke"
      }
  }

  "a reassigned reflection handle" should {
      lazy val cpg = code("""
        |import java.lang.reflect.Method;
        |public class Main {
        |  public void a(String s) {}
        |  public void b(String s) {}
        |  void run(boolean f, String tainted) throws Exception {
        |    Class<?> c = Class.forName("Main");
        |    Method m = c.getMethod("a", String.class);
        |    m = c.getMethod("b", String.class);
        |    m.invoke(this, tainted);
        |  }
        |}
        |""".stripMargin)

      "not be resolved to either candidate" in {
          cpg.method.name("run").ast.isCall.code("m.invoke.*").head.name shouldBe "invoke"
      }
  }
end ReflectionTests
