package io.appthreat.php2atom.passes

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Tests for [[PhpFrameworkTagsPass]] - the pass that turns the framework taint vocabulary declared
  * in `PhpFrameworkSemantics` into `framework-input` / `framework-output` / `sql` tags on the graph
  * (Requirements 6.2/6.3/6.4).
  *
  * The pass runs as part of `Php2Atom.createCpg`, so nothing in these tests registers it: the tags
  * asserted here are exactly the tags a real run produces.
  *
  * The negative cases matter as much as the positive ones. The declared vocabulary contains bare
  * call names (`input`, `all`, `query`, `post`, `get`, `raw`, `statement`) that also name ordinary
  * collection / ORM / HTTP-client methods, so the pass gates them on a receiver heuristic.
  */
class PhpFrameworkTagsPassTests extends PhpCode2CpgFixture:

  private val FrameworkInput  = "framework-input"
  private val FrameworkOutput = "framework-output"
  private val Sql             = "sql"

  "framework sources" should {

      "tag a qualified static request accessor (Request::input)" in {
          val cpg = code("""<?php
          |function handle() {
          |  return Request::input('name');
          |}
          |""".stripMargin)

          cpg.call.name("input").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      }

      "tag a namespace-qualified static request accessor" in {
          val cpg = code("""<?php
          |function handle() {
          |  return \App\Http\Request::input('name');
          |}
          |""".stripMargin)

          cpg.call.name("input").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      }

      "tag a bare accessor on a request-like receiver ($request->all)" in {
          val cpg = code("""<?php
          |function handle($request) {
          |  return $request->all();
          |}
          |""".stripMargin)

          cpg.call.name("all").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      }

      "tag a bare accessor on the request() helper (request()->query)" in {
          val cpg = code("""<?php
          |function handle() {
          |  return request()->query('page');
          |}
          |""".stripMargin)

          cpg.call.name("query").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      }

      "NOT tag the same bare accessor on a collection receiver ($collection->all)" in {
          val cpg = code("""<?php
          |function handle($collection) {
          |  return $collection->all();
          |}
          |""".stripMargin)

          cpg.call.name("all").where(_.tag.nameExact(FrameworkInput)).size shouldBe 0
      }

      "NOT tag ->get on an unrelated receiver ($cache->get)" in {
          val cpg = code("""<?php
          |function handle($cache) {
          |  return $cache->get('key');
          |}
          |""".stripMargin)

          cpg.call.name("get").where(_.tag.nameExact(FrameworkInput)).size shouldBe 0
      }

      "tag a superglobal read ($_POST)" in {
          val cpg = code("""<?php
          |function handle() {
          |  return $_POST['name'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 1
      }

      "tag an attacker-controlled $_SERVER read ($_SERVER['HTTP_REFERER'])" in {
          val cpg = code("""<?php
          |function handle() {
          |  return $_SERVER['HTTP_REFERER'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 1
      }

      "tag $_SERVER['REQUEST_URI']" in {
          val cpg = code("""<?php
          |function handle() {
          |  return $_SERVER['REQUEST_URI'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 1
      }

      "NOT tag a non-request $_SERVER key ($_SERVER['DOCUMENT_ROOT'])" in {
          val cpg = code("""<?php
          |function handle() {
          |  return $_SERVER['DOCUMENT_ROOT'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 0
      }

      "tag a dynamically keyed $_SERVER read (conservative)" in {
          val cpg = code("""<?php
          |function handle($key) {
          |  return $_SERVER[$key];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 1
      }

      "NOT tag an ordinary array read" in {
          val cpg = code("""<?php
          |function handle($items) {
          |  return $items['first'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 0
      }
  }

  "framework sinks" should {

      "tag a qualified raw query builder (DB::raw) as framework-output and sql" in {
          val cpg = code("""<?php
          |function handle($q) {
          |  DB::raw($q);
          |}
          |""".stripMargin)

          cpg.call.name("raw").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
          cpg.call.name("raw").where(_.tag.nameExact(Sql)).size shouldBe 1
      }

      "tag $wpdb->query and $wpdb->get_results" in {
          val cpg = code("""<?php
          |function handle($q) {
          |  $wpdb->query($q);
          |  $wpdb->get_results($q);
          |}
          |""".stripMargin)

          cpg.call.name("query").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
          cpg.call.name("get_results").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
          cpg.call.name("get_results").where(_.tag.nameExact(Sql)).size shouldBe 1
      }

      "tag echo output" in {
          val cpg = code("""<?php
          |function handle($q) {
          |  echo $q;
          |}
          |""".stripMargin)

          cpg.call.name("echo").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
      }

      "tag Doctrine createQuery" in {
          val cpg = code("""<?php
          |function handle($em, $q) {
          |  $em->createQuery($q);
          |}
          |""".stripMargin)

          cpg.call.name("createQuery").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
      }

      "NOT tag ->query on an unrelated receiver ($collection->query)" in {
          val cpg = code("""<?php
          |function handle($collection, $q) {
          |  $collection->query($q);
          |}
          |""".stripMargin)

          cpg.call.name("query").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 0
      }

      "NOT tag ->raw on an unrelated receiver ($twig->raw)" in {
          val cpg = code("""<?php
          |function handle($twig, $q) {
          |  $twig->raw($q);
          |}
          |""".stripMargin)

          cpg.call.name("raw").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 0
      }
  }

  "the pass" should {

      "leave a graph with no framework constructs untagged" in {
          val cpg = code("""<?php
          |function add($a, $b) {
          |  return $a + $b;
          |}
          |""".stripMargin)

          cpg.tag.name(FrameworkInput).size shouldBe 0
          cpg.tag.name(FrameworkOutput).size shouldBe 0
      }
  }
end PhpFrameworkTagsPassTests
