package io.appthreat.php2atom.parser

import io.appthreat.php2atom.parser.Domain.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Domain-level decode tests for task 12.1: reading the additive provenance keys off the generator
  * wrapper object and degrading unmapped nodes gracefully (Requirements 3.1, 3.5, 3.10, 4.1, 4.5;
  * design §2.6 / Error Handling).
  *
  * These feed the JSON contract straight into [[Domain.fromJson]] so they stay hermetic (no PHP
  * runtime required). Two top-level shapes are exercised: the new generator wrapper `{ "ast":
  * [...], ...provenance }` and the older bare statement array.
  */
class ProvenanceAndFallbackTests extends AnyWordSpec with Matchers:

  private def attributes(line: Int = 1, filePos: Int = 0): ujson.Obj =
      ujson.Obj("startLine" -> line, "startFilePos" -> filePos, "kind" -> 1)

  /** A trivially-decodable known statement (`Stmt_Nop`) used as inert filler. */
  private def nopStmt(line: Int = 1): ujson.Obj =
      ujson.Obj("nodeType" -> "Stmt_Nop", "attributes" -> attributes(line))

  /** The new generator per-file wrapper object. */
  private def wrapper(
    ast: ujson.Arr,
    extra: Map[String, ujson.Value] = Map.empty
  ): ujson.Obj =
    val obj = ujson.Obj(
      "ast"               -> ast,
      "parser_backend"    -> "nikic/php-parser@5.8.0",
      "generator_version" -> "2.0.0",
      "php_version"       -> "8.4.1",
      "target_version"    -> "8.4"
    )
    extra.foreach { case (k, v) => obj(k) = v }
    obj

  "Wrapper unwrapping and provenance" should {

      "unwrap the `ast` array and decode its statements (forward compatible)" in {
          val file = Domain.fromJson(wrapper(ujson.Arr(nopStmt(), nopStmt(2))))
          (file.children should have).length(2)
          all(file.children) shouldBe a[NopStmt]
      }

      "read the required provenance keys off the wrapper" in {
          val file = Domain.fromJson(wrapper(ujson.Arr(nopStmt())))
          file.provenance.parserBackend shouldBe Some("nikic/php-parser@5.8.0")
          file.provenance.generatorVersion shouldBe Some("2.0.0")
          file.provenance.phpVersion shouldBe Some("8.4.1")
          file.provenance.targetVersion shouldBe Some("8.4")
      }

      "read the optional per-file flags when present" in {
          val file = Domain.fromJson(
            wrapper(
              ujson.Arr(nopStmt()),
              extra = Map(
                "rel_file_path"     -> ujson.Str("src/A.php"),
                "encoding_scrubbed" -> ujson.Bool(true),
                "truncated_nodes"   -> ujson.Num(3)
              )
            )
          )
          file.provenance.relFilePath shouldBe Some("src/A.php")
          file.provenance.encodingScrubbed shouldBe true
          file.provenance.truncatedNodes shouldBe Some(3)
      }

      "treat every provenance key as optional (absent keys never fail decode)" in {
          // A wrapper carrying only `ast` — all provenance keys absent.
          val file = Domain.fromJson(ujson.Obj("ast" -> ujson.Arr(nopStmt())))
          (file.children should have).length(1)
          file.provenance.parserBackend shouldBe None
          file.provenance.generatorVersion shouldBe None
          file.provenance.phpVersion shouldBe None
          file.provenance.targetVersion shouldBe None
          file.provenance.relFilePath shouldBe None
          file.provenance.encodingScrubbed shouldBe false
          file.provenance.truncatedNodes shouldBe None
      }

      "treat a JSON-null target_version as unset" in {
          val file = Domain.fromJson(
            wrapper(ujson.Arr(nopStmt()), extra = Map("target_version" -> ujson.Null))
          )
          file.provenance.targetVersion shouldBe None
      }

      "decode a bare statement array with empty provenance (backward compatible)" in {
          val file = Domain.fromJson(ujson.Arr(nopStmt(), nopStmt(2)))
          (file.children should have).length(2)
          file.provenance shouldBe PhpProvenance.Empty
      }
  }

  "Unmapped-node fallback (contract additivity)" should {

      "degrade an unknown statement nodeType to NopStmt, retaining source attributes" in {
          val unknown = ujson.Obj(
            "nodeType"   -> "Stmt_FutureThing_9_9",
            "attributes" -> attributes(line = 42, filePos = 100)
          )
          val file = Domain.fromJson(ujson.Arr(unknown))
          file.children match
            case (nop: NopStmt) :: Nil =>
                nop.attributes.lineNumber.map(_.intValue) shouldBe Some(42)
                nop.attributes.columnNumber.map(_.intValue) shouldBe Some(100)
                nop.attributes.kind shouldBe Some(1)
            case other => fail(s"Expected a single NopStmt fallback but got: $other")
      }

      "degrade an unknown expression nodeType to a placeholder instead of crashing" in {
          // Wrap the unknown expression in a Stmt_Expression so it is decoded via readExpr.
          val unknownExpr = ujson.Obj(
            "nodeType"   -> "Expr_FutureOp_9_9",
            "attributes" -> attributes(line = 7, filePos = 20)
          )
          val stmt = ujson.Obj(
            "nodeType"   -> "Stmt_Expression",
            "expr"       -> unknownExpr,
            "attributes" -> attributes()
          )
          val file = Domain.fromJson(ujson.Arr(stmt))
          file.children match
            case (expr: PhpExpr) :: Nil =>
                expr.attributes.lineNumber.map(_.intValue) shouldBe Some(7)
                expr.attributes.columnNumber.map(_.intValue) shouldBe Some(20)
            case other => fail(s"Expected a single expression placeholder but got: $other")
      }

      "ignore an additive per-node `framework_facts` key without breaking decode" in {
          val enriched = ujson.Obj(
            "nodeType"        -> "Stmt_Nop",
            "framework_facts" -> ujson.Obj("superglobal" -> ujson.Str("$_GET")),
            "attributes"      -> attributes()
          )
          val file = Domain.fromJson(ujson.Arr(enriched))
          file.children match
            case (_: NopStmt) :: Nil => succeed
            case other               => fail(s"Expected a single NopStmt but got: $other")
      }

      "tolerate an object in statement position with no nodeType (degrade to Nop)" in {
          val noType = ujson.Obj("attributes" -> attributes())
          val file   = Domain.fromJson(ujson.Arr(noType))
          file.children match
            case (_: NopStmt) :: Nil => succeed
            case other               => fail(s"Expected a single NopStmt but got: $other")
      }
  }
end ProvenanceAndFallbackTests
