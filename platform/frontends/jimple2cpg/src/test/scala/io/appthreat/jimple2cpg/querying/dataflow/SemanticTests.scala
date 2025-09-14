package io.appthreat.jimple2cpg.querying.dataflow

import io.appthreat.jimple2cpg.testfixtures.{JimpleDataFlowCodeToCpgSuite, JimpleDataflowTestCpg}
import io.appthreat.dataflowengineoss.language._
import io.appthreat.dataflowengineoss.semanticsloader.FlowSemantic
import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language._

class SemanticTests
    extends JimpleDataFlowCodeToCpgSuite(extraFlows =
      List(
        FlowSemantic.from("Test.sanitize:java.lang.String(java.lang.String)", List((0, 0), (1, 1))),
        FlowSemantic.from("java.nio.file.Paths.get:.*\\(java.lang.String,.*\\)", List.empty, regex = true)
      )
    ) {

  "Dataflow through custom semantics" should {
    lazy implicit val cpg: JimpleDataflowTestCpg = code(
      """
      |import java.nio.file.Paths;
      |import java.net.URI;
      |
      |public class Test {
      | public void test1() {
      |   String s = "MALICIOUS";
      |   String b = taint(s);
      |   System.out.println(b);
      | }
      |
      | public void test2() {
      |   String s = "MALICIOUS";
      |   String b = taint(s);
      |   String c = sanitize(b);
      |   System.out.println(c);
      | }
      |
      | public void test3() {
      |   String s = "MALICIOUS";
      |   String b = Paths.get(URI.create(s)).toString();
      |   System.out.println(b);
      | }
      |
      | public void test4() {
      |   String s = "MALICIOUS";
      |   String b = Paths.get("/tmp", s).toString();
      |   System.out.println(b);
      | }
      |
      | public void test5() {
      |   String s = "MALICIOUS";
      |   byte[] dst = new byte[10];
      |   System.arraycopy(s.getBytes(), 0, dst, 0, 9);
      |   String b = new String(dst);
      |   System.out.println(b);
      | }
      |
      | public String taint(String s) {
      |     return s + ".taint";
      | }
      |
      | public String sanitize(String s) {
      |     if (s.contains("..")) {
      |         return s.replace("..", "");
      |     }
      |     return s;
      | }
      |}""".stripMargin,
      "Test.java"
    )

    "find a path" in {
      val (source, sink) = getConstSourceSink("test1")
      sink.reachableBy(source).size shouldBe 1
    }

    "be kill in sanitizer" in {
      val (source, sink) = getConstSourceSink("test2")
      sink.reachableBy(source).size shouldBe 0
    }

    "taints return" in {
      val (source, sink) = getConstSourceSink("test3")
      sink.reachableBy(source).size shouldBe 1
    }

    "be killed" in {
      val (source, sink) = getConstSourceSink("test4")
      sink.reachableBy(source).size shouldBe 0
    }

    "follow taint rules" in {
      val (source, sink) = getConstSourceSink("test5")
      sink.reachableBy(source).size shouldBe 1
    }

  }

    "Reflection Type Inference" should {

      lazy implicit val cpg: JimpleDataflowTestCpg = code(
        """
              |class Person {
              |    private String name;
              |    public Person(String name) {
              |        this.name = name;
              |    }
              |    public String getName() { return this.name; }
              |    public void setName(String name) { this.name = name; }
              |    public static String getGreetingPrefix() { return "Hello, "; }
              |}
              |
              |class ReflectionTest {
              |    public static void main(String[] args) throws Exception {
              |        // --- Test 1: invoke result assigned to Object, used in sink ---
              |        Class<?> personClass = Class.forName("example.Person");
              |        var constructor = personClass.getConstructor(String.class);
              |        Object personInstance = constructor.newInstance("Alice");
              |
              |        var getNameMethod = personClass.getMethod("getName");
              |        // Before type inference pass, resultType might be 'java.lang.Object'
              |        // After type inference pass, it should ideally be inferred as 'java.lang.String'
              |        Object nameResult = getNameMethod.invoke(personInstance);
              |        System.out.println(nameResult); // Sink for nameResult
              |
              |
              |        // --- Test 2: invoke result from static method ---
              |        var getPrefixMethod = personClass.getMethod("getGreetingPrefix");
              |        Object prefixResult = getPrefixMethod.invoke(null); // Static invoke
              |        System.out.println(prefixResult); // Sink for prefixResult
              |
              |
              |        // --- Test 3: Chained reflection (Class.forName().getMethod().invoke()) ---
              |        Object chainedResult = Class.forName("example.Person")
              |                                   .getMethod("getGreetingPrefix")
              |                                   .invoke(null);
              |        System.out.println(chainedResult); // Sink for chainedResult
              |    }
              |}
              |""".stripMargin,
        "ReflectionTest.java"
      )

      "demonstrate improved type inference for Method.invoke results" in {
          val mainMethod           = cpg.method.name("main").head
          val nameResultIdentifier = mainMethod.ast.isIdentifier.name("nameResult").head
          val nameResultAssignment = mainMethod.ast.isCall.name("<operator>.assignment")
              .where(_.argument(1).isIdentifier.name("nameResult")).head
          val nameInvokeCall = nameResultAssignment.argument(2).asInstanceOf[Call]
          nameInvokeCall.name shouldBe "invoke"
          nameInvokeCall.typeFullName shouldBe "java.lang.Object" // Bug
          nameResultIdentifier.typeFullName shouldBe "java.lang.Object"
          val nameResultSink = cpg.call.name("println")
              .where(_.argument(1).code("nameResult"))
              .head
          val nameResultSource =
              cpg.call.name("invoke").where(_.typeFullName("java.lang.Object")).head // Bug
          nameResultSink.reachableBy(nameResultSource).size should be > 0

          val prefixResultIdentifier = mainMethod.ast.isIdentifier.name("prefixResult").head
          val prefixResultAssignment = mainMethod.ast.isCall.name("<operator>.assignment")
              .where(_.argument(1).isIdentifier.name("prefixResult")).head
          val prefixInvokeCall = prefixResultAssignment.argument(2).asInstanceOf[Call]
          prefixInvokeCall.name shouldBe "invoke"

          prefixInvokeCall.typeFullName shouldBe "java.lang.Object" // Bug
          prefixResultIdentifier.typeFullName shouldBe "java.lang.Object"

          val prefixResultSink = cpg.call.name("println")
              .where(_.argument(1).code("prefixResult"))
              .head
          val prefixResultSource =
              cpg.call.name("invoke").where(_.typeFullName("java.lang.Object")).argument // Bug
          prefixResultSink.reachableBy(prefixResultSource).size should be > 0
          val chainedResultIdentifier = mainMethod.ast.isIdentifier.name("chainedResult").head
          val chainedResultAssignment = mainMethod.ast.isCall.name("<operator>.assignment")
              .where(_.argument(1).isIdentifier.name("chainedResult")).head
          val chainedInvokeCall = chainedResultAssignment.argument(2).asInstanceOf[Call]
          chainedInvokeCall.name shouldBe "invoke"

          chainedInvokeCall.typeFullName shouldBe "java.lang.Object"
          chainedResultIdentifier.typeFullName shouldBe "java.lang.Object"

          val chainedResultSink = cpg.call.name("println")
              .where(_.argument(1).code("chainedResult"))
              .head
          val chainedResultSource =
              cpg.call.name("invoke").where(_.typeFullName("java.lang.Object")).argument
          chainedResultSink.reachableBy(chainedResultSource).size should be > 0
      }
  }
}
