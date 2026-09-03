package io.appthreat.php2atom.passes

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.appthreat.x2cpg.passes.taggers.ChennaiTagsPass
import io.shiftleft.semanticcpg.language.*

/** Framework-entrypoint tagging tests for PHP (php-support-upgrade task 22.1, Requirement 6.5 /
  * design Decision 3).
  *
  * `ChennaiTagsPass.tagPhpRoutes` maps two additional PHP entrypoint shapes to the tag-driven
  * "policy" atom consumes:
  *   - PHP 8+ attribute routes (`#[Route(...)]`, `#[Get(...)]`, ... on Symfony/Laravel controllers)
  *     -> the routed method is tagged `framework-route` and its parameters `framework-input`.
  *   - WordPress hook registrations (`add_action`/`add_filter`) -> the registered callable (2nd
  *     argument) is tagged `framework-route`, and where that callable is a string literal naming a
  *     function in the graph, that function's parameters are tagged `framework-input`.
  *
  * Each test builds a small PHP CPG then runs `new ChennaiTagsPass(cpg).createAndApply()` before
  * asserting the tags, so the assertions exercise the real tagging pass end to end.
  */
class FrameworkEntrypointTaggingTests extends PhpCode2CpgFixture:

  private val FrameworkRoute = "framework-route"
  private val FrameworkInput = "framework-input"

  "attribute routes" should {

      "tag a controller method annotated #[Route(\"/users\")] as framework-route and its params as framework-input" in {
          val cpg = code("""<?php
          |class UserController {
          |  #[Route("/users")]
          |  public function index($id) {
          |    return $id;
          |  }
          |}
          |""".stripMargin)
          new ChennaiTagsPass(cpg).createAndApply()

          cpg.method.name("index").where(_.tag.nameExact(FrameworkRoute)).nonEmpty shouldBe true
          cpg.method.name("index").parameter.name("id").where(
            _.tag.nameExact(FrameworkInput)
          ).nonEmpty shouldBe true
      }

      "tag a method annotated with an HTTP-verb attribute #[Get(\"/x\")] as framework-route" in {
          val cpg = code("""<?php
          |class ApiController {
          |  #[Get("/x")]
          |  public function show($slug) {
          |    return $slug;
          |  }
          |}
          |""".stripMargin)
          new ChennaiTagsPass(cpg).createAndApply()

          cpg.method.name("show").where(_.tag.nameExact(FrameworkRoute)).nonEmpty shouldBe true
      }

      "tag a method annotated with a fully-qualified route attribute as framework-route" in {
          val cpg = code("""<?php
          |class FqController {
          |  #[\Symfony\Component\Routing\Annotation\Route("/fq")]
          |  public function fq($id) {
          |    return $id;
          |  }
          |}
          |""".stripMargin)
          new ChennaiTagsPass(cpg).createAndApply()

          cpg.method.name("fq").where(_.tag.nameExact(FrameworkRoute)).nonEmpty shouldBe true
      }

      "NOT tag a method annotated only #[Deprecated] as framework-route (negative case)" in {
          val cpg = code("""<?php
          |class LegacyController {
          |  #[\Deprecated]
          |  public function old($id) {
          |    return $id;
          |  }
          |}
          |""".stripMargin)
          new ChennaiTagsPass(cpg).createAndApply()

          cpg.method.name("old").where(_.tag.nameExact(FrameworkRoute)).isEmpty shouldBe true
      }
  }

  "WordPress hooks" should {

      "tag the callable argument of add_action('init', 'my_handler') as framework-route" in {
          val cpg = code("""<?php
          |function my_handler($data) {
          |  return $data;
          |}
          |add_action('init', 'my_handler');
          |""".stripMargin)
          new ChennaiTagsPass(cpg).createAndApply()

          // The registration surfaces via a framework-route tag on the pass.
          cpg.tag.name(FrameworkRoute).nonEmpty shouldBe true
          // The callable (2nd argument) literal is the tagged entrypoint.
          cpg.call.name("add_action").argument.argumentIndex(2).where(
            _.tag.nameExact(FrameworkRoute)
          ).nonEmpty shouldBe true
          // The resolvable handler's parameters are treated as web-facing input.
          cpg.method.name("my_handler").parameter.name("data").where(
            _.tag.nameExact(FrameworkInput)
          ).nonEmpty shouldBe true
      }

      "tag the callable argument of add_filter(...) as framework-route" in {
          val cpg = code("""<?php
          |function filter_title($title) {
          |  return $title;
          |}
          |add_filter('the_title', 'filter_title');
          |""".stripMargin)
          new ChennaiTagsPass(cpg).createAndApply()

          cpg.call.name("add_filter").argument.argumentIndex(2).where(
            _.tag.nameExact(FrameworkRoute)
          ).nonEmpty shouldBe true
      }
  }
end FrameworkEntrypointTaggingTests
