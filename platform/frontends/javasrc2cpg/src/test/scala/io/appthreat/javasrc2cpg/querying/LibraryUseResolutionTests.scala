package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.{Config, JavaSrc2Cpg, JavaSrc2CpgTestContext}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.utils.ProjectRoot
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

/** The javasrc2cpg resolution gaps that hid library uses (chen#245): each shape with a bad twin,
  * which must produce the resolved record, and a good twin, which must not produce a wrong one.
  */
class LibraryUseResolutionTests extends AnyFreeSpec with Matchers:

  private val stubJar =
      ProjectRoot.relativise("platform/frontends/javasrc2cpg/src/test/resources/Stub.jar")

  private def callOf(cpg: Cpg, name: String): Call = cpg.call.nameExact(name).head

  private def buildCpg(source: String): Cpg =
      JavaSrc2CpgTestContext.buildCpg(source, inferenceJarPaths = Set(stubJar))

  "a java.lang name under a single wildcard import" - {
      lazy val cpg = JavaSrc2CpgTestContext.buildCpg("""
          |import stub.*;
          |
          |public class Widget {
          |  @Override
          |  public String toString() { return "w"; }
          |
          |  @Deprecated
          |  void old() {}
          |
          |  @SuppressWarnings("all")
          |  void quiet() {}
          |
          |  @SafeVarargs
          |  final void safe(String... parts) {}
          |}
          |""".stripMargin)

      "resolve each java.lang annotation, not a member of the wildcard package" in {
          cpg.annotation.fullName.l.sorted shouldBe List(
            "java.lang.Deprecated",
            "java.lang.Override",
            "java.lang.SafeVarargs",
            "java.lang.SuppressWarnings"
          )
      }
  }

  "an explicit single-type import" - {
      lazy val cpg = JavaSrc2CpgTestContext.buildCpg("""
          |import stub.Override;
          |
          |public class Widget {
          |  @Override
          |  void run() {}
          |}
          |""".stripMargin)

      "still beat java.lang" in {
          cpg.annotation.fullName.l shouldBe List("stub.Override")
      }
  }

  "calls in field initialisers" - {
      lazy val cpg = buildCpg("""
          |import org.slf4j.Logger;
          |import org.slf4j.LoggerFactory;
          |import stub.Security;
          |
          |public class Widget {
          |  private static final Logger LOGGER = LoggerFactory.getLogger(Widget.class);
          |  private Security sec = new Security();
          |  private int versionLength = Security.VERSION.length();
          |
          |  void use() {}
          |}
          |""".stripMargin)

      "resolve the static initialiser's call in <clinit>" in {
          val Seq(clinit) = cpg.typeDecl.name("Widget").head.method.nameExact("<clinit>").l
          val getLogger   = clinit.call.nameExact("getLogger").head
          getLogger.methodFullName shouldBe
              "org.slf4j.LoggerFactory.getLogger:org.slf4j.Logger(java.lang.Class)"
      }

      "resolve the instance initialiser's constructor and call" in {
          val init = cpg.typeDecl.name("Widget").head.method.nameExact("<init>").head
          init.call.nameExact("<init>").methodFullName.l should contain(
            "stub.Security.<init>:void()"
          )
          init.call.nameExact("length").methodFullName.l shouldBe List(
            "java.lang.String.length:int()"
          )
      }
  }

  "a chain on an external return type" - {
      lazy val cpg = buildCpg("""
          |import stub.Security;
          |import stub.FormLogin;
          |
          |public class Widget {
          |  private Security sec = new Security();
          |
          |  void configure() {
          |    sec.formLogin().loginPage("/x");
          |    Security.http().formLogin().loginPage("/y");
          |    FormLogin fl = sec.formLogin();
          |    fl.loginPage("/z");
          |  }
          |}
          |""".stripMargin)

      "resolve every link from the previous link's declared return type" in {
          cpg.call.nameExact("formLogin").methodFullName.l.toSet shouldBe Set(
            "stub.Security.formLogin:stub.FormLogin()"
          )
          cpg.call.nameExact("loginPage").methodFullName.l.toSet shouldBe Set(
            "stub.FormLogin.loginPage:stub.FormLogin(java.lang.String)"
          )
      }
  }

  "parameter annotations" - {
      lazy val cpg = JavaSrc2CpgTestContext.buildCpg("""
          |import stub.RequestParam;
          |
          |public class Widget {
          |  void handle(@RequestParam("id") String id, @RequestParam(required = false) String name) {}
          |}
          |""".stripMargin)

      "carry their full names" in {
          val params = cpg.parameter.nameExact("id", "name").l
          params.map(_.annotation.fullName.head).toSet shouldBe Set("stub.RequestParam")
      }
  }

  "Lombok members" - {
      lazy val cpg = buildCpg("""
          |import lombok.Data;
          |import lombok.Getter;
          |import lombok.extern.slf4j.Slf4j;
          |import stub.Security;
          |
          |@Slf4j
          |@Data
          |public class Cart {
          |  private String owner;
          |  private boolean paid;
          |  private final int serial;
          |  private Security security;
          |
          |  void use(Cart other) {
          |    log.info("cart for " + getOwner());
          |    setOwner("me");
          |    setPaid(true);
          |    getSecurity().login("me");
          |    getSerial();
          |    other.getSecurity().login("me");
          |  }
          |}
          |""".stripMargin)

      "give the generated log field its type, so log.info resolves" in {
          cpg.member.name("log").typeFullName.l shouldBe List("org.slf4j.Logger")
          val info = callOf(cpg, "info")
          info.methodFullName shouldBe "org.slf4j.Logger.info:void(java.lang.String)"
      }

      "generate the accessors of @Data, isX for a boolean, none for a final field" in {
          cpg.method.fullName.l should contain("Cart.getOwner:java.lang.String()")
          cpg.method.fullName.l should contain("Cart.setOwner:void(java.lang.String)")
          cpg.method.fullName.l should contain("Cart.isPaid:boolean()")
          cpg.method.fullName.l should contain("Cart.setPaid:void(boolean)")
          cpg.method.fullName.l should contain("Cart.getSerial:int()")
          // a final field has no setter; the graph must not invent one
          cpg.method.name("setSerial").size shouldBe 0
      }

      "resolve a chain through a getter's return type" in {
          val login = callOf(cpg, "login")
          login.methodFullName shouldBe "stub.Security.login:void(java.lang.String)"
      }

      "not generate an accessor the type declares itself" in {
          // the good twin: an explicit member wins over the generated one
          val explicit = JavaSrc2CpgTestContext.buildCpg("""
              |import lombok.Data;
              |
              |@Data
              |public class Named {
              |  private String name;
              |
              |  public String getName() { return name.toUpperCase(); }
              |}
              |""".stripMargin)
          explicit.method.fullName.l.count(_.startsWith("Named.getName")) shouldBe 1
      }
  }

  "a Lombok accessor of another file" - {
      // Two files: the getter is generated in Order.java, the chain is written in Shop.java.
      // JavaParser resolves per compilation unit, so the link after the getter is left to the
      // graph passes.
      lazy val cpg =
        val dir = java.nio.file.Files.createTempDirectory("lombok-cross-file").toFile
        java.nio.file.Files.write(
          new java.io.File(dir, "Item.java").toPath,
          """public class Item {
              |  private String name;
              |
              |  public String getName() { return name; }
              |}
              |""".stripMargin.getBytes
        )
        java.nio.file.Files.write(
          new java.io.File(dir, "Order.java").toPath,
          """import lombok.Data;
              |
              |@Data
              |public class Order {
              |  private Item item;
              |}
              |""".stripMargin.getBytes
        )
        java.nio.file.Files.write(
          new java.io.File(dir, "Shop.java").toPath,
          """public class Shop {
              |  void ship(Order order) {
              |    order.getItem().getName();
              |  }
              |}
              |""".stripMargin.getBytes
        )
        val javaSrc2Cpg = JavaSrc2Cpg()
        val config = Config(inferenceJarPaths = Set(stubJar))
            .withInputPath(dir.getAbsolutePath)
            .withOutputPath("")
        javaSrc2Cpg.createCpgWithOverlays(config).get
      end cpg

      "resolve the call after the generated getter" in {
          cpg.call.nameExact("getItem").methodFullName.head shouldBe
              "Order.getItem:Item()"
          cpg.call.nameExact("getName").methodFullName.head shouldBe
              "Item.getName:java.lang.String()"
      }
  }
end LibraryUseResolutionTests
