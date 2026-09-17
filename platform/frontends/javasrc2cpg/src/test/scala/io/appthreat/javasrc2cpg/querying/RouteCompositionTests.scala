package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** The route a handler actually serves, recorded as a `route-path` tag on the handler method. */
class RouteCompositionTests extends JavaSrcCode2CpgFixture:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def routesOf(cpg: Cpg, method: String): List[String] =
      cpg.method.name(method).tag.nameExact("route-path").value.l.sorted

  private def verbsOf(cpg: Cpg, method: String): List[String] =
      cpg.method.name(method).tag.nameExact("http-method").value.l.sorted

  "a Spring controller with a class-level prefix" should {
      lazy val cpg = tagged(code(
        """
        |package com.example;
        |import org.springframework.web.bind.annotation.*;
        |@RestController
        |@RequestMapping("/api/v1")
        |public class UserController {
        |    @GetMapping("/users")
        |    public String list() { return ""; }
        |
        |    @PostMapping("users/{id}")
        |    public String create(@PathVariable String id) { return id; }
        |
        |    @DeleteMapping
        |    public String removeAll() { return ""; }
        |}
        |""".stripMargin,
        "UserController.java"
      ))

      "compose the prefix onto an absolute method path" in {
          routesOf(cpg, "list") shouldBe List("/api/v1/users")
      }

      "compose the prefix onto a relative method path" in {
          routesOf(cpg, "create") shouldBe List("/api/v1/users/{id}")
      }

      "use the prefix alone when the method declares no path" in {
          routesOf(cpg, "removeAll") shouldBe List("/api/v1")
      }

      "record the verb the mapping annotation names" in {
          verbsOf(cpg, "list") shouldBe List("GET")
          verbsOf(cpg, "create") shouldBe List("POST")
          verbsOf(cpg, "removeAll") shouldBe List("DELETE")
      }
  }

  "a Spring controller without a class-level prefix" should {
      lazy val cpg = tagged(code(
        """
        |package com.example;
        |import org.springframework.web.bind.annotation.*;
        |@RestController
        |public class PingController {
        |    @GetMapping("/ping")
        |    public String ping() { return "pong"; }
        |}
        |""".stripMargin,
        "PingController.java"
      ))

      "keep the method path as the route" in {
          routesOf(cpg, "ping") shouldBe List("/ping")
      }
  }

  "a mapping that declares several paths" should {
      lazy val cpg = tagged(code(
        """
        |package com.example;
        |import org.springframework.web.bind.annotation.*;
        |@RestController
        |@RequestMapping({"/api", "/v2"})
        |public class MultiController {
        |    @GetMapping({"/a", "/b"})
        |    public String many() { return ""; }
        |}
        |""".stripMargin,
        "MultiController.java"
      ))

      "record every combination that exists at runtime" in {
          routesOf(cpg, "many") shouldBe List("/api/a", "/api/b", "/v2/a", "/v2/b")
      }
  }

  "a @RequestMapping with no verb" should {
      lazy val cpg = tagged(code(
        """
        |package com.example;
        |import org.springframework.web.bind.annotation.*;
        |@RestController
        |public class AnyVerbController {
        |    @RequestMapping("/any")
        |    public String any() { return ""; }
        |}
        |""".stripMargin,
        "AnyVerbController.java"
      ))

      "record the route but claim no verb" in {
          routesOf(cpg, "any") shouldBe List("/any")
          verbsOf(cpg, "any") shouldBe empty
      }
  }

  "a JAX-RS resource with a class-level @Path" should {
      lazy val cpg = tagged(code(
        """
        |package com.example;
        |import jakarta.ws.rs.GET;
        |import jakarta.ws.rs.Path;
        |import jakarta.ws.rs.QueryParam;
        |@Path("/orders")
        |public class OrderResource {
        |    @GET
        |    @Path("/{id}")
        |    public String get(@QueryParam("id") String id) { return id; }
        |}
        |""".stripMargin,
        "OrderResource.java"
      ))

      "compose the resource path onto the method path" in {
          routesOf(cpg, "get") shouldBe List("/orders/{id}")
      }

      "record the verb annotation" in {
          verbsOf(cpg, "get") shouldBe List("GET")
      }
  }
end RouteCompositionTests
