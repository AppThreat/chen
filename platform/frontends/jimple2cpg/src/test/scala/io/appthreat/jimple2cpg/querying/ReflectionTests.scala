package io.appthreat.jimple2cpg.querying

import io.appthreat.jimple2cpg.testfixtures.JimpleCode2CpgFixture
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Literal, Identifier}
import io.shiftleft.proto.cpg.Cpg.DispatchTypes
import io.shiftleft.semanticcpg.language._

class ReflectionTests extends JimpleCode2CpgFixture {

  val cpg: Cpg = code("""
      |class Foo {
      | static int add(int x, int y) {
      |   return x + y;
      | }
      |
      | static void foo() throws NoSuchMethodException {
      |   var fooClazz = Foo.class;
      |   var fooMethod = fooClazz.getMethod("add", int.class, int.class);
      | }
      |}
      |""".stripMargin).cpg

    "should assign the class and method variables correctly" in {
        val identifiers = cpg.method("foo").ast.isIdentifier.name("fooClazz", "fooMethod").l
        identifiers.size should be >= 2
        val identifierMap = identifiers.groupBy(_.name).view.mapValues(_.head).toMap
        val fooClazz = identifierMap.getOrElse("fooClazz", fail("Identifier 'fooClazz' not found"))
        val fooMethod = identifierMap.getOrElse("fooMethod", fail("Identifier 'fooMethod' not found"))
        fooClazz shouldBe a[Identifier]
        fooClazz.typeFullName shouldBe "java.lang.Class"
        fooClazz.parentExpression match {
            case Some(assignmentCall: Call) if assignmentCall.name == "<operator>.assignment" =>
                val rhsLiteralOpt = assignmentCall.ast.isLiteral.headOption
                rhsLiteralOpt match {
                    case Some(classLiteral: Literal) =>
                        classLiteral.code shouldBe "Foo.class"
                        classLiteral.typeFullName shouldBe "java.lang.Class"
                    case None => fail("RHS of fooClazz assignment should contain a class literal 'Foo.class'")
                }
            case _ => fail("fooClazz identifier should be the LHS (child) of an <operator>.assignment call")
        }
        fooMethod shouldBe a[Identifier]
        fooMethod.typeFullName shouldBe "java.lang.reflect.Method"
    }

    "should handle chained reflection calls like Class.forName().getMethod().invoke()" in {
        val cpg: Cpg = code("""
                                   |class Greeter {
                                   |    public static String greet(String who) {
                                   |        return "Hello, " + who;
                                   |    }
                                   |    public static void main(String[] args) throws Exception {
                                   |        String who = "World";
                                   |        Object result = Class.forName("example.Greeter")
                                   |                                .getMethod("greet", String.class)
                                   |                                .invoke(null, who);
                                   |        System.out.println(result);
                                   |    }
                                   |}
                                   |""".stripMargin).cpg
        val mainMethod = cpg.method.name("main").head
        val resultAssignment = mainMethod.ast.isCall.name("<operator>.assignment")
            .where(_.argument(1).isIdentifier.name("result"))
            .head

        val invokeCall = resultAssignment.argument(2).asInstanceOf[Call]
        invokeCall.name shouldBe "invoke"
        invokeCall.methodFullName shouldBe "java.lang.reflect.Method.invoke:java.lang.Object(java.lang.Object,java.lang.Object[])"
        invokeCall.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH.toString
        val getMethodCalls = mainMethod.call.name("getMethod").l
        getMethodCalls should not be empty
        val getMethodCall = getMethodCalls.head
        getMethodCall.name shouldBe "getMethod"
        getMethodCall.typeFullName shouldBe "java.lang.reflect.Method" // Bug
        val forNameCalls = mainMethod.call.name("forName").l
        forNameCalls should not be empty
        val forNameCall = forNameCalls.head
        forNameCall.name shouldBe "forName"
        forNameCall.methodFullName should include("java.lang.Class.forName:")
        val getMethodArgs = getMethodCall.argument.l.filter(_.argumentIndex > 0).sortBy(_.argumentIndex)
        getMethodArgs.size shouldBe 2
        getMethodArgs(0).code shouldBe "\"greet\""
        val invokeArgs = invokeCall.argument.l.filter(_.argumentIndex > 0).sortBy(_.argumentIndex)
        invokeArgs.size shouldBe 2
        invokeArgs(0).code shouldBe "null"
        val whoIdentifierOpt = invokeArgs.find(_.isInstanceOf[Identifier]).map(_.asInstanceOf[Identifier])
        whoIdentifierOpt shouldBe defined
    }

    "should handle chained reflection with custom object return type" in {
        val cpg: Cpg = code("""
                                        |// Custom class to be instantiated reflectively
                                        |class Person {
                                        |    private String name;
                                        |    public Person(String name) {
                                        |        this.name = name;
                                        |    }
                                        |    public String getName() { return this.name; }
                                        |    public void setName(String name) { this.name = name; }
                                        |}
                                        |
                                        |class PersonFactory {
                                        |    public static void main(String[] args) throws Exception {
                                        |        // Chained reflection to create a Person instance
                                        |        // Class.forName("example.Person").getConstructor(String.class).newInstance("Alice");
                                        |        Class<?> personClass = Class.forName("example.Person");
                                        |        var constructor = personClass.getConstructor(String.class);
                                        |        Object personInstance = constructor.newInstance("Alice");
                                        |
                                        |        // Chained reflection to call getName
                                        |        var getNameMethod = personClass.getMethod("getName");
                                        |        Object nameResult = getNameMethod.invoke(personInstance);
                                        |
                                        |        // Use results to ensure they are in the graph
                                        |        System.out.println(nameResult);
                                        |        System.out.println(personInstance.toString());
                                        |    }
                                        |}
                                        |""".stripMargin).cpg

        val mainMethod = cpg.method.name("main").head
        val personInstanceAssignment = mainMethod.ast.isCall.name("<operator>.assignment")
            .where(_.argument(1).isIdentifier.name("personInstance"))
            .head
        val newInstanceCall = personInstanceAssignment.argument(2).asInstanceOf[Call]
        newInstanceCall.name shouldBe "newInstance"
        val personInstanceIdentifier = mainMethod.ast.isIdentifier.name("personInstance").head
        personInstanceIdentifier.typeFullName shouldBe "java.lang.Object"
        newInstanceCall.typeFullName shouldBe "java.lang.Object"
        val nameResultAssignment = mainMethod.ast.isCall.name("<operator>.assignment")
            .where(_.argument(1).isIdentifier.name("nameResult"))
            .head
        val invokeCall = nameResultAssignment.argument(2).asInstanceOf[Call]
        invokeCall.name shouldBe "invoke"
        invokeCall.typeFullName shouldBe "java.lang.Object"
        val nameResultIdentifier = mainMethod.ast.isIdentifier.name("nameResult").head
        nameResultIdentifier.typeFullName shouldBe "java.lang.Object"

        val getConstructorCalls = mainMethod.call.name("getConstructor").l
        getConstructorCalls should not be empty
        val getConstructorCall = getConstructorCalls.head
        getConstructorCall.typeFullName shouldBe "java.lang.reflect.Constructor"
        val getMethodCalls = mainMethod.call.name("getMethod").l
        getMethodCalls should not be empty
        val getMethodCall = getMethodCalls.head
        getMethodCall.typeFullName shouldBe "java.lang.reflect.Method" // Bug
        val newInstanceArgs = newInstanceCall.argument.l.filter(_.argumentIndex > 0).sortBy(_.argumentIndex)
        newInstanceArgs.size shouldBe 1
        val invokeArgs = invokeCall.argument.l.filter(_.argumentIndex > 0).sortBy(_.argumentIndex)
        invokeArgs.size shouldBe 2
    }
}
