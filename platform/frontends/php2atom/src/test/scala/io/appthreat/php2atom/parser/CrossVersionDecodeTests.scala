package io.appthreat.php2atom.parser

import io.appthreat.php2atom.parser.Domain.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Explicit two-directional cross-version decode-compatibility guard (Requirements 4.2, 4.5; design
  * Decision 4).
  *
  * Where [[ProvenanceAndFallbackTests]] (task 12.1) pins wrapper-unwrap + node fallback in
  * isolation and [[ContractAdditivityTests]] (task 12.4) exercises additivity generatively, this
  * suite frames the contract as the two concrete cross-version directions the decoder must survive:
  *
  *   1. OLDER chen reads NEWER-generator output — a wrapper carrying future/unknown provenance keys
  *      and an `ast` mixing known nodes with an unknown future `nodeType` and additive per-node
  *      keys. Unknowns are ignored / degraded; known nodes and modeled provenance still decode. 2.
  *      NEWER chen reads OLDER-generator output — a bare top-level statement array (the pre-wrapper
  *      shape older phpastgen emitted) with only classic node types and none of the newer optional
  *      fields. It decodes with `PhpProvenance.Empty` and additive fields default to empty.
  *
  * A third case pins that an unknown `nodeType` in either statement or expression position degrades
  * (Nop / placeholder) rather than crashing — the invariant that makes both directions safe.
  *
  * All fixtures are fed straight to [[Domain.fromJson]] so the suite is hermetic (no PHP runtime).
  */
class CrossVersionDecodeTests extends AnyWordSpec with Matchers:

  private def attributes(line: Int = 1, filePos: Int = 0): ujson.Obj =
      ujson.Obj("startLine" -> line, "startFilePos" -> filePos, "kind" -> 1)

  /** A trivially-decodable known statement (`Stmt_Nop`) used as inert filler. */
  private def nopStmt(line: Int = 1): ujson.Obj =
      ujson.Obj("nodeType" -> "Stmt_Nop", "attributes" -> attributes(line))

  /** An `Stmt_Echo` carrying a single scalar — a classic, always-modeled statement used to prove
    * known nodes still decode alongside unknown ones.
    */
  private def echoStmt(line: Int = 3): ujson.Obj =
      ujson.Obj(
        "nodeType" -> "Stmt_Echo",
        "exprs" -> ujson.Arr(
          ujson.Obj(
            "nodeType"   -> "Scalar_Int",
            "value"      -> 1,
            "attributes" -> attributes(line)
          )
        ),
        "attributes" -> attributes(line)
      )

  // ---------------------------------------------------------------------------
  // Direction 1: older chen reads newer-generator output.
  // ---------------------------------------------------------------------------

  "Cross-version decode: older chen reading newer-generator output (Requirements 4.2, 4.5)" should {

      /** A newer-generator wrapper: current provenance PLUS a future/unknown provenance key, and an
        * `ast` that mixes a known statement, an unknown future statement `nodeType`, and a node
        * carrying an additive per-node `framework_facts` key.
        */
      def newerWrapper: ujson.Obj =
          ujson.Obj(
            // Modeled provenance keys this chen understands.
            "ast" -> ujson.Arr(
              echoStmt(),
              // Additive per-node enrichment key an older chen must ignore.
              ujson.Obj(
                "nodeType"        -> "Stmt_Nop",
                "framework_facts" -> ujson.Obj("route" -> ujson.Str("/health")),
                "attributes"      -> attributes(2)
              ),
              // A future statement nodeType this chen does not model.
              ujson.Obj(
                "nodeType"   -> "Stmt_FutureThing",
                "attributes" -> attributes(line = 42, filePos = 100)
              )
            ),
            "parser_backend"    -> "nikic/php-parser@6.0.0",
            "generator_version" -> "3.0.0",
            "php_version"       -> "8.6.0",
            "target_version"    -> "8.6",
            // A future/unknown provenance key this chen does not model — must be ignored.
            "future_meta" -> ujson.Obj(
              "capabilities" -> ujson.Arr("lazy-objects", "new-in-initializers"),
              "schema"       -> ujson.Str("v3")
            )
          )

      "decode successfully, ignoring the unknown top-level provenance key" in {
          val file = Domain.fromJson(newerWrapper)
          // Decode does not throw and the ast is unwrapped.
          (file.children should have).length(3)
      }

      "read the modeled provenance while ignoring the unknown provenance key" in {
          val file = Domain.fromJson(newerWrapper)
          file.provenance.parserBackend shouldBe Some("nikic/php-parser@6.0.0")
          file.provenance.generatorVersion shouldBe Some("3.0.0")
          file.provenance.phpVersion shouldBe Some("8.6.0")
          file.provenance.targetVersion shouldBe Some("8.6")
          // The unknown `future_meta` provenance key is silently ignored: nothing about it leaks into
          // the modeled provenance, and it did not fail the decode.
      }

      "decode known nodes to their types and degrade the unknown future nodeType to NopStmt" in {
          val file = Domain.fromJson(newerWrapper)
          file.children match
            case (echo: PhpEchoStmt) :: (facts: NopStmt) :: (future: NopStmt) :: Nil =>
                // The additive `framework_facts` sibling key was ignored (still a plain Nop).
                facts.attributes.lineNumber.map(_.intValue) shouldBe Some(2)
                // The unknown future statement degraded to a NopStmt, retaining its source attributes.
                future.attributes.lineNumber.map(_.intValue) shouldBe Some(42)
                future.attributes.columnNumber.map(_.intValue) shouldBe Some(100)
                future.attributes.kind shouldBe Some(1)
                echo.attributes.lineNumber.map(_.intValue) shouldBe Some(3)
            case other =>
                fail(s"Expected [PhpEchoStmt, NopStmt, NopStmt] but got: $other")
      }
  }

  // ---------------------------------------------------------------------------
  // Direction 2: newer chen reads older-generator output.
  // ---------------------------------------------------------------------------

  "Cross-version decode: newer chen reading older-generator output (Requirements 4.2, 4.5)" should {

      /** A property node in the OLDER shape: it omits the newer optional keys entirely (`hooks`,
        * `attrGroups`) so it exercises additive tolerance in the backward direction.
        */
      def olderProperty: ujson.Obj =
          ujson.Obj(
            "nodeType" -> "Stmt_Property",
            "flags"    -> 1, // Modifiers::PUBLIC
            "type" -> ujson.Obj(
              "nodeType"   -> "Identifier",
              "name"       -> "string",
              "attributes" -> attributes()
            ),
            "props" -> ujson.Arr(
              ujson.Obj(
                "nodeType" -> "PropertyItem",
                "name" -> ujson.Obj(
                  "nodeType"   -> "VarLikeIdentifier",
                  "name"       -> "x",
                  "attributes" -> attributes()
                ),
                "default"    -> ujson.Null,
                "attributes" -> attributes()
              )
            ),
            // NOTE: no `hooks`, no `attrGroups` keys at all — the pre-8.4 / pre-wrapper shape.
            "attributes" -> attributes()
          )

      /** The older bare top-level statement array: no wrapper object, no provenance, no per-node
        * enrichment keys — only classic node types.
        */
      def olderBareArray: ujson.Arr =
          ujson.Arr(nopStmt(), echoStmt(), olderProperty)

      "decode a bare top-level array with PhpProvenance.Empty" in {
          val file = Domain.fromJson(olderBareArray)
          (file.children should have).length(3)
          file.provenance shouldBe PhpProvenance.Empty
      }

      "decode the classic children as expected" in {
          val file = Domain.fromJson(olderBareArray)
          file.children match
            case (_: NopStmt) :: (_: PhpEchoStmt) :: (_: PhpPropertyStmt) :: Nil => succeed
            case other => fail(s"Expected [NopStmt, PhpEchoStmt, PhpPropertyStmt] but got: $other")
      }

      "default the newer optional property fields when the older shape omits them" in {
          val file = Domain.fromJson(ujson.Arr(olderProperty))
          file.children match
            case (prop: PhpPropertyStmt) :: Nil =>
                prop.hooks shouldBe Nil
                prop.attributeGroups shouldBe Nil
                prop.asymmetricVisibility shouldBe None
            case other => fail(s"Expected a single PhpPropertyStmt but got: $other")
      }
  }

  // ---------------------------------------------------------------------------
  // Cross-cutting invariant: unknown nodeType degrades, never crashes.
  // ---------------------------------------------------------------------------

  "Cross-version decode: an unknown nodeType degrades rather than crashing (Requirements 4.2, 4.5)" should {

      "degrade an unknown statement nodeType to NopStmt without throwing" in {
          val unknownStmt = ujson.Obj(
            "nodeType"   -> "Stmt_FromTheFuture",
            "attributes" -> attributes(line = 11, filePos = 5)
          )
          val file = Domain.fromJson(ujson.Arr(unknownStmt))
          file.children match
            case (nop: NopStmt) :: Nil =>
                nop.attributes.lineNumber.map(_.intValue) shouldBe Some(11)
                nop.attributes.columnNumber.map(_.intValue) shouldBe Some(5)
            case other => fail(s"Expected a single NopStmt but got: $other")
      }

      "degrade an unknown expression nodeType to a placeholder without throwing" in {
          // Wrap the unknown expression in a Stmt_Expression so it is decoded via readExpr.
          val stmt = ujson.Obj(
            "nodeType" -> "Stmt_Expression",
            "expr" -> ujson.Obj(
              "nodeType"   -> "Expr_FromTheFuture",
              "attributes" -> attributes(line = 9, filePos = 3)
            ),
            "attributes" -> attributes()
          )
          val file = Domain.fromJson(ujson.Arr(stmt))
          file.children match
            case (expr: PhpExpr) :: Nil =>
                expr.attributes.lineNumber.map(_.intValue) shouldBe Some(9)
                expr.attributes.columnNumber.map(_.intValue) shouldBe Some(3)
            case other => fail(s"Expected a single expression placeholder but got: $other")
      }
  }
end CrossVersionDecodeTests
