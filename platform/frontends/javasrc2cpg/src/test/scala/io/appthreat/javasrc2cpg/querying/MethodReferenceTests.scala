package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Method references (`Foo::bar`, `Foo::new`, atom#334): the METHOD_REF node's full name names the
  * referenced method when the solver binds it, and a constructor reference that the solver cannot
  * bind still names its declaring type with the `<init>` member, read off the scope expression.
  */
class MethodReferenceTests extends JavaSrcCode2CpgFixture:

  "a method reference the solver binds" should {
      val cpg = code("""
        |import java.util.function.Consumer;
        |
        |public class Foo {
        |  void usesRefs() {
        |    use(String::valueOf);
        |    use(this::helper);
        |  }
        |
        |  void helper() {}
        |  void use(Consumer<Object> c) { c.accept("x"); }
        |}
        |""".stripMargin)

      "carry the referenced method's full name" in {
          val refs = cpg.methodRef.l
          refs.map(_.code).sorted shouldBe List("String::valueOf", "this::helper")
          refs.filter(_.code == "String::valueOf").map(_.methodFullName).l shouldBe List(
            "java.lang.String.valueOf:java.lang.String(java.lang.Object)"
          )
          refs.filter(_.code == "this::helper").map(_.methodFullName).l shouldBe
              List("Foo.helper:void()")
      }
  }

  "a constructor reference the solver cannot bind" should {
      val cpg = code("""
        |import java.util.function.Supplier;
        |
        |public class Bar {
        |  void usesCtorRef() {
        |    Supplier<String> s = String::new;
        |    Supplier<Bar> b = Bar::new;
        |  }
        |}
        |""".stripMargin)

      "carry the declaring type with the <init> member" in {
          val refs = cpg.methodRef.l.sortBy(_.code)
          refs.map(_.code) shouldBe List("Bar::new", "String::new")
          refs.map(_.methodFullName) shouldBe List(
            "Bar.<init>:<unresolvedSignature>(0)",
            "java.lang.String.<init>:<unresolvedSignature>(0)"
          )
      }
  }

  "a bound receiver reference" should {
      val cpg = code("""
        |import java.util.function.Consumer;
        |
        |public class Baz {
        |  void usesBound(Consumer<Object> c) {
        |    use(System.out::println);
        |  }
        |  void use(Consumer<Object> c) { c.accept("x"); }
        |}
        |""".stripMargin)

      "carry the receiver type's method" in {
          cpg.methodRef.methodFullName.l shouldBe List(
            "java.io.PrintStream.println:void(java.lang.Object)"
          )
      }
  }
end MethodReferenceTests
