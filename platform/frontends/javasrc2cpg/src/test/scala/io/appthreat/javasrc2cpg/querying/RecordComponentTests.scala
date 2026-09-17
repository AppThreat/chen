package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*

/** The members, accessors and canonical constructor a record declares implicitly. */
class RecordComponentTests extends JavaSrcCode2CpgFixture(withOssDataflow = true):

  "a record with components" should {
      lazy val cpg = code("""
        |public record User(String name, int age) {
        |  String shout() { return name.toUpperCase(); }
        |}
        |""".stripMargin)

      "declare a member per component" in {
          cpg.typeDecl.nameExact("User").member.l.map(m =>
              m.name -> m.typeFullName
          ) shouldBe List("name" -> "java.lang.String", "age" -> "int")
      }

      "declare an accessor per component" in {
          cpg.method.fullNameExact("User.name:java.lang.String()").size shouldBe 1
          cpg.method.fullNameExact("User.age:int()").size shouldBe 1
      }

      "declare the canonical constructor rather than a no-arg default" in {
          cpg.typeDecl.nameExact("User").method.nameExact("<init>").fullName.l shouldBe List(
            "User.<init>:void(java.lang.String,int)"
          )
      }

      "give the accessor a body that reads its component" in {
          cpg.method.fullNameExact("User.name:java.lang.String()").ast.isFieldIdentifier
              .canonicalName.l shouldBe List("name")
      }

      "describe itself as a record" in {
          cpg.typeDecl.nameExact("User").head.code shouldBe "public record User"
      }
  }

  "a record whose accessor is declared explicitly" should {
      lazy val cpg = code("""
        |public record User(String name) {
        |  public String name() { return name.trim(); }
        |}
        |""".stripMargin)

      "keep the declared accessor and not generate a second one" in {
          val accessors = cpg.method.nameExact("name").l
          accessors.size shouldBe 1
          accessors.head.ast.isCall.name.l should contain("trim")
      }
  }

  "a record with a compact constructor" should {
      lazy val cpg = code("""
        |public record User(String name) {
        |  public User { if (name == null) throw new IllegalArgumentException(); }
        |}
        |""".stripMargin)

      "fold the compact body into a single canonical constructor" in {
          val constructors = cpg.typeDecl.nameExact("User").method.nameExact("<init>").l
          constructors.size shouldBe 1
          constructors.head.fullName shouldBe "User.<init>:void(java.lang.String)"
      }

      "keep the compact body's validation ahead of the component assignment" in {
          val body = cpg.typeDecl.nameExact("User").method.nameExact("<init>").head
          body.ast.isControlStructure.size shouldBe 1
          body.ast.isCall.name(".*assignment").code.l should contain("this.name = name")
      }
  }

  "taint through a record" should {
      lazy val cpg = code("""
        |public class Main {
        |  record User(String name, int age) {}
        |  void go(String tainted) {
        |    User u = new User(tainted, 1);
        |    System.out.println(u.name());
        |  }
        |}
        |""".stripMargin)

      "resolve the construction to the canonical constructor" in {
          cpg.call.nameExact("<init>").methodFullName.l should contain(
            "Main$User.<init>:void(java.lang.String,int)"
          )
      }

      "reach a sink reading the component back out" in {
          def source = cpg.method.name("go").parameter.name("tainted")
          cpg.call.name("println").argument(1).reachableBy(source).size should be > 0
      }
  }
end RecordComponentTests
