package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** Calls made on a JDK dynamic proxy, routed to the invocation handler that serves them. */
class DynamicProxyTests extends JavaSrcCode2CpgFixture(withOssDataflow = true):

  private def taintFromParam(cpg: Cpg, method: String, param: String): Int =
    def source = cpg.method.name(method).parameter.name(param)
    cpg.call.name("println").argument(1).reachableBy(source).size

  "a proxy created with an inline handler" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |class Handler implements InvocationHandler {
        |  public Object invoke(Object proxy, Method m, Object[] args) {
        |    System.out.println((String) args[0]);
        |    return null;
        |  }
        |}
        |public class Main {
        |  void go(String tainted) {
        |    Service s = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, new Handler());
        |    s.run(tainted);
        |  }
        |}
        |""".stripMargin)

      "rewrite the proxied call onto the handler's invoke" in {
          val call = cpg.method.name("go").ast.isCall.code("s.run.*").head
          call.name shouldBe "invoke"
          call.methodFullName shouldBe
              "Handler.invoke:java.lang.Object(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
      }

      "pass the proxied arguments to the handler's args parameter" in {
          val call = cpg.method.name("go").ast.isCall.code("s.run.*").head
          call.argument.l.map(a => a.argumentIndex -> a.code) shouldBe List(
            0 -> "s",
            3 -> "tainted"
          )
      }

      "link the call graph through to the handler" in {
          cpg.method.name("go").ast.isCall.code("s.run.*").callee(using NoResolve).name.l should
              contain("invoke")
      }

      "carry taint into the handler body" in {
          taintFromParam(cpg, "go", "tainted") should be > 0
      }
  }

  "a proxy whose handler is held in a local" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |class Handler implements InvocationHandler {
        |  public Object invoke(Object proxy, Method m, Object[] args) {
        |    System.out.println((String) args[0]);
        |    return null;
        |  }
        |}
        |public class Main {
        |  void go(String tainted) {
        |    Handler h = new Handler();
        |    Service s = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, h);
        |    s.run(tainted);
        |  }
        |}
        |""".stripMargin)

      "carry taint into the handler body" in {
          taintFromParam(cpg, "go", "tainted") should be > 0
      }
  }

  "a proxied method with several arguments" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String first, String second); }
        |class Handler implements InvocationHandler {
        |  public Object invoke(Object proxy, Method m, Object[] args) {
        |    System.out.println((String) args[1]);
        |    return null;
        |  }
        |}
        |public class Main {
        |  void go(String tainted) {
        |    Service s = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, new Handler());
        |    s.run("safe", tainted);
        |  }
        |}
        |""".stripMargin)

      "carry taint from any argument, since all of them land in args" in {
          taintFromParam(cpg, "go", "tainted") should be > 0
      }
  }

  "a proxy whose handler cannot be named" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |public class Main {
        |  void go(String tainted, InvocationHandler supplied) {
        |    Service s = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, supplied);
        |    s.run(tainted);
        |  }
        |}
        |""".stripMargin)

      "be left alone rather than guessed at" in {
          cpg.method.name("go").ast.isCall.code("s.run.*").head.name shouldBe "run"
      }
  }

  "a proxy created with an anonymous inline handler" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |public class Main {
        |  void go(String tainted) {
        |    Service s = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, new InvocationHandler() {
        |        public Object invoke(Object proxy, Method m, Object[] args) {
        |          System.out.println((String) args[0]);
        |          return null;
        |        }
        |      });
        |    s.run(tainted);
        |  }
        |}
        |""".stripMargin)

      "carry taint into the anonymous handler body" in {
          taintFromParam(cpg, "go", "tainted") should be > 0
      }

      "rewrite onto the anonymous class's invoke, not the interface's" in {
          val call = cpg.method.name("go").ast.isCall.code("s.run.*").head
          call.name shouldBe "invoke"
          call.methodFullName shouldBe
              "Main$1.invoke:java.lang.Object(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
      }
  }

  "a handler local declared as the handler interface" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |class Handler implements InvocationHandler {
        |  public Object invoke(Object proxy, Method m, Object[] args) {
        |    System.out.println((String) args[0]);
        |    return null;
        |  }
        |}
        |public class Main {
        |  void go(String tainted) {
        |    InvocationHandler h = new Handler();
        |    Service s = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, h);
        |    s.run(tainted);
        |  }
        |}
        |""".stripMargin)

      "be resolved from the one constructor it was assigned" in {
          taintFromParam(cpg, "go", "tainted") should be > 0
      }
  }

  "a handler local whose right side could name several types" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |class HandlerA implements InvocationHandler {
        |  public Object invoke(Object proxy, Method m, Object[] args) {
        |    System.out.println((String) args[0]);
        |    return null;
        |  }
        |}
        |class HandlerB extends HandlerA {}
        |public class Main {
        |  void go(String tainted, boolean which) {
        |    InvocationHandler h = which ? new HandlerA() : new HandlerB();
        |    Service s = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, h);
        |    s.run(tainted);
        |  }
        |}
        |""".stripMargin)

      "be left alone rather than guessed at" in {
          cpg.method.name("go").ast.isCall.code("s.run.*").head.name shouldBe "run"
      }
  }

  "a proxy held in a field of the class that created it" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |class Handler implements InvocationHandler {
        |  public Object invoke(Object proxy, Method m, Object[] args) {
        |    System.out.println((String) args[0]);
        |    return null;
        |  }
        |}
        |public class Main {
        |  private final Service service;
        |  private Service bare;
        |  private Service setter;
        |  private Service contested;
        |  Main() {
        |    service = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, new Handler());
        |    this.bare = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, new Handler());
        |    contested = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, new Handler());
        |  }
        |  void useField(String tainted) { service.run(tainted); }
        |  void useThisField(String tainted) { this.service.run(tainted); }
        |  void useBare(String tainted) { bare.run(tainted); }
        |  void useSetter(String tainted) { setter.run(tainted); }
        |  void setSetter(Service s) { this.setter = s; }
        |  void reset(String tainted) { contested = null; contested.run(tainted); }
        |}
        |""".stripMargin)

      "carry taint from a call on the bare field name" in {
          taintFromParam(cpg, "useField", "tainted") should be > 0
      }

      "carry taint from a call on this.field" in {
          taintFromParam(cpg, "useThisField", "tainted") should be > 0
      }

      "carry taint for a field written without the this prefix" in {
          taintFromParam(cpg, "useBare", "tainted") should be > 0
      }

      "leave a field that another method also writes alone" in {
          cpg.method.name("useSetter").ast.isCall.code("setter.run.*").head.name shouldBe "run"
      }

      "leave a field that is also written with null alone" in {
          cpg.method.name("reset").ast.isCall.code("contested.run.*").head.name shouldBe "run"
      }
  }

  "a class that is its own handler" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |public class Main implements InvocationHandler {
        |  private final Service service;
        |  Main() {
        |    service = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, this);
        |  }
        |  public Object invoke(Object proxy, Method m, Object[] args) {
        |    System.out.println((String) args[0]);
        |    return null;
        |  }
        |  void use(String tainted) { service.run(tainted); }
        |}
        |""".stripMargin)

      "route the proxied calls to its own invoke" in {
          taintFromParam(cpg, "use", "tainted") should be > 0
      }
  }

  "a field that a local shadows" should {
      lazy val cpg = code("""
        |import java.lang.reflect.*;
        |interface Service { void run(String s); }
        |class Handler implements InvocationHandler {
        |  public Object invoke(Object proxy, Method m, Object[] args) {
        |    System.out.println((String) args[0]);
        |    return null;
        |  }
        |}
        |public class Main {
        |  private final Service service = (Service) Proxy.newProxyInstance(
        |      Main.class.getClassLoader(), new Class[]{Service.class}, new Handler());
        |  void shadowed(String tainted) {
        |    Service service = null;
        |    service.run(tainted);
        |  }
        |  void unshadowed(String tainted) { service.run(tainted); }
        |}
        |""".stripMargin)

      "rewrite the field read but not the shadowing local" in {
          cpg.method.name("shadowed").ast.isCall.code("service.run.*").head.name shouldBe "run"
          taintFromParam(cpg, "unshadowed", "tainted") should be > 0
      }
  }
end DynamicProxyTests
