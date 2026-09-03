package io.appthreat.php2atom.dataflow

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import io.shiftleft.semanticcpg.language.*
import io.appthreat.dataflowengineoss.language.*

/** Framework taint dataflow tests (php-support-upgrade task 21.2, Requirements 6.2/6.3/6.4).
  *
  * For each framework (Laravel, Symfony, WordPress) two behaviours are asserted:
  *   - unsanitized: a framework SOURCE reaches a framework SINK with no sanitizer on the path -> a
  *     tainted flow is reported (`reachableByFlows(...).nonEmpty`).
  *   - sanitized: the same source is routed through the framework SANITIZER before the sink -> NO
  *     flow (`size == 0`), proving the sanitizer semantics in `DefaultSemantics.phpFlows` clear
  *     taint through the OSS dataflow layer. Those flows only reach a PHP graph, via
  *     `DefaultSemantics.flowsForLanguage`, so these cases also prove the language-scoped wiring is
  *     intact.
  *
  * Sources and sinks are located through the TAGS produced by
  * `io.appthreat.php2atom.passes.PhpFrameworkTagsPass` (`framework-input` / `framework-output`),
  * not by hardcoded call names, so a tagging regression fails these tests. The pass is part of
  * `Php2Atom.createCpg`, which is what the fixture and every real run go through - no test-only
  * glue registers it here.
  *
  * Every test also asserts the source and sink sets are non-empty. Without that, a broken tagging
  * pass would make the "sanitized" expectations (`size shouldBe 0`) pass for the wrong reason.
  *
  * The source/sink/sanitizer vocabulary lives in
  * io.appthreat.dataflowengineoss.semantics.PhpFrameworkSemantics.
  */
class FrameworkTaintDataflowTests extends PhpCode2CpgFixture(runOssDataflow = true):

  private val FrameworkInput  = "framework-input"
  private val FrameworkOutput = "framework-output"
  private val Sql             = "sql"

  private def taggedSources(cpg: Cpg): Iterator[CfgNode] =
      cpg.tag.name(FrameworkInput).call

  private def taggedSinks(cpg: Cpg): Iterator[CfgNode] =
      cpg.tag.name(FrameworkOutput).call

  // ---------------------------------------------------------------------------
  // Laravel: source Request::input / request()->input ; sink DB::raw ; sanitizer e()
  // ---------------------------------------------------------------------------

  "Laravel: unsanitized Request::input reaching DB::raw is reported" in {
      val cpg = code("""<?php
        |function handle() {
        |  $name = Request::input('name');
        |  DB::raw($name);
        |}
        |""".stripMargin)

      cpg.call.name("input").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      cpg.call.name("raw").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
      // A raw query builder is a SQL sink, so it also carries the more specific `sql` category tag.
      cpg.call.name("raw").where(_.tag.nameExact(Sql)).size shouldBe 1

      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size should be >= 1
  }

  "Laravel: Request::input sanitized with e() does NOT reach DB::raw" in {
      val cpg = code("""<?php
        |function handle() {
        |  $name = Request::input('name');
        |  $safe = e($name);
        |  DB::raw($safe);
        |}
        |""".stripMargin)

      taggedSources(cpg).size should be >= 1
      taggedSinks(cpg).size should be >= 1
      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size shouldBe 0
  }

  "Laravel: unsanitized request()->input reaching DB::raw is reported" in {
      val cpg = code("""<?php
        |function handle() {
        |  $name = request()->input('name');
        |  DB::raw($name);
        |}
        |""".stripMargin)

      // Bare call name `input`, accepted because the receiver looks like a request object.
      cpg.call.name("input").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size should be >= 1
  }

  // ---------------------------------------------------------------------------
  // Symfony: source Request::get ; sink raw Doctrine DQL ($em->createQuery)
  // Symfony has no free-function sanitizer in the design (escaping is done by the
  // templating/binding layer), so only the unsanitized flow is asserted here.
  // ---------------------------------------------------------------------------

  "Symfony: unsanitized Request::get reaching createQuery (raw DQL) is reported" in {
      val cpg = code("""<?php
        |function listAction() {
        |  $q = Request::get('q');
        |  $em->createQuery($q);
        |}
        |""".stripMargin)

      cpg.call.name("get").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      cpg.call.name("createQuery").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1

      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size should be >= 1
  }

  "Symfony: Request::get sanitized with htmlspecialchars does NOT reach createQuery" in {
      val cpg = code("""<?php
        |function listAction() {
        |  $q = Request::get('q');
        |  $safe = htmlspecialchars($q);
        |  $em->createQuery($safe);
        |}
        |""".stripMargin)

      taggedSources(cpg).size should be >= 1
      taggedSinks(cpg).size should be >= 1
      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size shouldBe 0
  }

  // ---------------------------------------------------------------------------
  // WordPress: source $_GET / $_SERVER ; sink echo / wpdb->query ;
  //            sanitizer esc_html / sanitize_text_field
  // ---------------------------------------------------------------------------

  "WordPress: unsanitized $_GET reaching echo is reported" in {
      val cpg = code("""<?php
        |function handler() {
        |  $q = $_GET['q'];
        |  echo $q;
        |}
        |""".stripMargin)

      cpg.call.nameExact("<operator>.indexAccess").where(
        _.tag.nameExact(FrameworkInput)
      ).size shouldBe 1
      cpg.call.name("echo").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1

      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size should be >= 1
  }

  "WordPress: $_GET sanitized with esc_html does NOT reach echo" in {
      val cpg = code("""<?php
        |function handler() {
        |  $q = $_GET['q'];
        |  $safe = esc_html($q);
        |  echo $safe;
        |}
        |""".stripMargin)

      taggedSources(cpg).size should be >= 1
      taggedSinks(cpg).size should be >= 1
      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size shouldBe 0
  }

  "WordPress: unsanitized $_GET reaching wpdb->query is reported" in {
      val cpg = code("""<?php
        |function handler() {
        |  $q = $_GET['q'];
        |  $wpdb->query($q);
        |}
        |""".stripMargin)

      cpg.call.name("query").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
      cpg.call.name("query").where(_.tag.nameExact(Sql)).size shouldBe 1

      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size should be >= 1
  }

  "WordPress: $_GET sanitized with sanitize_text_field does NOT reach wpdb->query" in {
      val cpg = code("""<?php
        |function handler() {
        |  $q = $_GET['q'];
        |  $s = sanitize_text_field($q);
        |  $wpdb->query($s);
        |}
        |""".stripMargin)

      taggedSources(cpg).size should be >= 1
      taggedSinks(cpg).size should be >= 1
      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size shouldBe 0
  }

  "WordPress: unsanitized $_SERVER['HTTP_REFERER'] reaching wpdb->get_results is reported" in {
      val cpg = code("""<?php
        |function handler() {
        |  $ref = $_SERVER['HTTP_REFERER'];
        |  $wpdb->get_results($ref);
        |}
        |""".stripMargin)

      cpg.call.nameExact("<operator>.indexAccess").where(
        _.tag.nameExact(FrameworkInput)
      ).size shouldBe 1
      cpg.call.name("get_results").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1

      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size should be >= 1
  }

  "WordPress: $_SERVER['HTTP_REFERER'] sanitized with esc_url does NOT reach echo" in {
      val cpg = code("""<?php
        |function handler() {
        |  $ref = $_SERVER['HTTP_REFERER'];
        |  $safe = esc_url($ref);
        |  echo $safe;
        |}
        |""".stripMargin)

      taggedSources(cpg).size should be >= 1
      taggedSinks(cpg).size should be >= 1
      taggedSinks(cpg).reachableByFlows(taggedSources(cpg)).size shouldBe 0
  }
end FrameworkTaintDataflowTests
