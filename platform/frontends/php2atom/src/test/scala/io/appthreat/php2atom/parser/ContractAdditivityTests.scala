package io.appthreat.php2atom.parser

import io.appthreat.php2atom.parser.Domain.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.util.{Random, Try}

/** Property test for task 12.4 — Property 1 (P1): Contract additivity.
  *
  * P1 statement: an unknown/newer `nodeType` degrades gracefully (decode never crashes); known
  * nodes still decode; unknown sibling keys are ignored; and this holds in BOTH directions —
  * older-reads-newer (a newer generator wrapper `{ ast: [...], ...extra provenance }` read by this
  * decoder) and newer-reads-older (a bare/known node carrying additive sibling keys). Validates
  * Requirements 4.1, 4.2.
  *
  * Task 12.1 implemented the behaviour under test in [[Domain]]: an unmapped statement `nodeType`
  * degrades to [[NopStmt]] (retaining attributes); an unmapped expression `nodeType` (reached via a
  * `Stmt_Expression` wrapper) degrades to a [[PhpNameExpr]] placeholder; the generator wrapper `{
  * ast: [...], ...provenance }` is unwrapped and unknown provenance/sibling keys are ignored.
  *
  * NOTE: this is a hand-rolled GENERATIVE scalatest test (many randomized cases driven by
  * [[scala.util.Random]]) rather than a ScalaCheck spec — ScalaCheck is NOT declared in php2atom's
  * `build.sbt` and is not on the classpath, so we cannot use it here. The structure mirrors the
  * existing [[ProvenanceAndFallbackTests]] in this package (`AnyWordSpec` + `Matchers`).
  */
class ContractAdditivityTests extends AnyWordSpec with Matchers:

  /** Number of randomized cases driven per property. */
  private val Iterations = 500

  /** Deterministic RNG so a failure is reproducible from the seed printed below. */
  private val seed = 0x9e3779b97f4a7c15L
  private val rng  = new Random(seed)

  private def attributes(line: Int, filePos: Int): ujson.Obj =
      ujson.Obj("startLine" -> line, "startFilePos" -> filePos, "kind" -> 1)

  /** Known nodeType prefixes/keywords the decoder models. A generated "unknown" nodeType must not
    * collide with any of these, otherwise the generator would accidentally exercise a real branch.
    */
  private val knownPrefixes = List("Stmt_", "Expr_", "Scalar_", "InterpolatedStringPart", "Name")

  private def looksKnown(nodeType: String): Boolean =
      knownPrefixes.exists(nodeType.startsWith)

  /** Generate a gibberish `nodeType` string guaranteed NOT to match a modeled type. We prefix with
    * a marker that no real nikic nodeType uses, then append random alphanumerics, and defensively
    * re-roll on the astronomically-unlikely chance it still looks known.
    */
  private def gibberishNodeType(): String =
    val alphabet = ('a' to 'z') ++ ('A' to 'Z') ++ ('0' to '9') ++ Seq('_', '$', '\\')
    def randomChunk(): String =
      val len = 1 + rng.nextInt(24)
      (0 until len).map(_ => alphabet(rng.nextInt(alphabet.length))).mkString
    var candidate = s"Zzz_Future_${randomChunk()}"
    while looksKnown(candidate) do candidate = s"Zzz_Future_${randomChunk()}"
    candidate

  /** A random JSON scalar value used to fill additive sibling keys. */
  private def randomJsonValue(): ujson.Value =
      rng.nextInt(4) match
        case 0 => ujson.Str(rng.alphanumeric.take(1 + rng.nextInt(12)).mkString)
        case 1 => ujson.Num(rng.nextInt(100000) - 50000)
        case 2 => ujson.Bool(rng.nextBoolean())
        case _ => ujson.Arr((0 until rng.nextInt(3)).map(_ =>
                ujson.Str(rng.alphanumeric.take(3).mkString)
            )*)

  /** Random extra sibling keys (name -> value) that must be ignored by decode. Key names are kept
    * clear of the real contract keys the decoder reads.
    */
  private val reservedKeys =
      Set(
        "nodeType",
        "attributes",
        "expr",
        "ast",
        "parser_backend",
        "generator_version",
        "php_version",
        "target_version",
        "rel_file_path",
        "encoding_scrubbed",
        "truncated_nodes"
      )

  private def randomExtraKeys(): Map[String, ujson.Value] =
    val count = rng.nextInt(4)
    (0 until count)
        .map { _ =>
          var key = "x_" + rng.alphanumeric.take(1 + rng.nextInt(10)).mkString
          while reservedKeys.contains(key) do key = "x_" + rng.alphanumeric.take(6).mkString
          key -> randomJsonValue()
        }
        .toMap

  /** A realistic additive per-node enrichment object the future generator may attach. */
  private def frameworkFacts(): ujson.Obj =
      ujson.Obj(
        "superglobal" -> ujson.Str(Seq("$_GET", "$_POST", "$_REQUEST", "$_SERVER")(rng.nextInt(4))),
        "confidence"  -> ujson.Num(rng.nextInt(101))
      )

  /** Decode `node` inside a fresh file and fail the test (rather than propagate) if it throws. */
  private def decodeNeverThrows(node: ujson.Value, clue: String): PhpFile =
      Try(Domain.fromJson(ujson.Arr(node)))
          .recover { case t =>
              fail(s"decode threw for $clue (seed=$seed): ${t.getClass.getName}: ${t.getMessage}")
          }
          .get

  s"Contract additivity (P1), $Iterations randomized cases per property, seed=$seed" should {

      "degrade an arbitrary unknown STATEMENT nodeType to NopStmt without ever throwing" in {
          (0 until Iterations).foreach { _ =>
            val line    = rng.nextInt(10000)
            val filePos = rng.nextInt(100000)
            val node = ujson.Obj(
              "nodeType"   -> gibberishNodeType(),
              "attributes" -> attributes(line, filePos)
            )
            // Sometimes also attach additive sibling keys — they must not change the outcome.
            randomExtraKeys().foreach { case (k, v) => node(k) = v }

            val file = decodeNeverThrows(node, "unknown statement nodeType")
            file.children match
              case (nop: NopStmt) :: Nil =>
                  nop.attributes.lineNumber.map(_.intValue) shouldBe Some(line)
                  nop.attributes.columnNumber.map(_.intValue) shouldBe Some(filePos)
              case other =>
                  fail(s"Expected a single NopStmt fallback but got: $other (seed=$seed)")
          }
      }

      "degrade an arbitrary unknown EXPRESSION nodeType to a placeholder without ever throwing" in {
          (0 until Iterations).foreach { _ =>
            val line    = rng.nextInt(10000)
            val filePos = rng.nextInt(100000)
            val unknownExpr = ujson.Obj(
              "nodeType"   -> gibberishNodeType(),
              "attributes" -> attributes(line, filePos)
            )
            randomExtraKeys().foreach { case (k, v) => unknownExpr(k) = v }
            // Wrap in Stmt_Expression so the unknown expr is decoded via readExpr.
            val stmt = ujson.Obj(
              "nodeType"   -> "Stmt_Expression",
              "expr"       -> unknownExpr,
              "attributes" -> attributes(line, filePos)
            )

            val file = decodeNeverThrows(stmt, "unknown expression nodeType")
            file.children match
              case (expr: PhpExpr) :: Nil =>
                  expr.attributes.lineNumber.map(_.intValue) shouldBe Some(line)
                  expr.attributes.columnNumber.map(_.intValue) shouldBe Some(filePos)
              case other =>
                  fail(s"Expected a single expression placeholder but got: $other (seed=$seed)")
          }
      }

      "keep decoding a KNOWN node to the same type when arbitrary unknown sibling keys are added" in {
          (0 until Iterations).foreach { _ =>
              // Alternate between a known statement (Stmt_Nop) and a known expression
              // (Scalar_Int wrapped in Stmt_Expression) so additivity is exercised on both paths.
              if rng.nextBoolean() then
                val node = ujson.Obj(
                  "nodeType"        -> "Stmt_Nop",
                  "attributes"      -> attributes(rng.nextInt(1000), rng.nextInt(1000)),
                  "framework_facts" -> frameworkFacts()
                )
                randomExtraKeys().foreach { case (k, v) => node(k) = v }
                val file = decodeNeverThrows(node, "known Stmt_Nop with extra sibling keys")
                file.children match
                  case (_: NopStmt) :: Nil => succeed
                  case other => fail(s"Expected a single NopStmt but got: $other (seed=$seed)")
              else
                val value = rng.nextInt(1000000)
                val intExpr = ujson.Obj(
                  "nodeType"        -> "Scalar_Int",
                  "value"           -> value,
                  "attributes"      -> attributes(rng.nextInt(1000), rng.nextInt(1000)),
                  "framework_facts" -> frameworkFacts()
                )
                randomExtraKeys().foreach { case (k, v) => intExpr(k) = v }
                val stmt = ujson.Obj(
                  "nodeType"   -> "Stmt_Expression",
                  "expr"       -> intExpr,
                  "attributes" -> attributes(1, 0)
                )
                val file = decodeNeverThrows(stmt, "known Scalar_Int with extra sibling keys")
                file.children match
                  case (i: PhpInt) :: Nil => i.value shouldBe value.toString
                  case other => fail(s"Expected a single PhpInt but got: $other (seed=$seed)")
          }
      }

      "older-reads-newer: unwrap `ast` and ignore arbitrary extra provenance keys without throwing" in {
          (0 until Iterations).foreach { _ =>
            // A newer generator wrapper carrying a couple of known statements plus arbitrary
            // future provenance keys the current decoder does not model.
            val stmtCount = 1 + rng.nextInt(4)
            val stmts = (0 until stmtCount).map { i =>
                ujson.Obj(
                  "nodeType"   -> "Stmt_Nop",
                  "attributes" -> attributes(i + 1, i * 10)
                ): ujson.Value
            }
            val wrapper = ujson.Obj(
              "ast"               -> ujson.Arr(stmts*),
              "parser_backend"    -> "nikic/php-parser@5.8.0",
              "generator_version" -> "2.0.0"
            )
            // Arbitrary additive/future provenance keys — must be ignored.
            randomExtraKeys().foreach { case (k, v) => wrapper(k) = v }

            val file = Try(Domain.fromJson(wrapper))
                .recover { case t =>
                    fail(
                      s"decode threw for newer wrapper (seed=$seed): ${t.getClass.getName}: ${t.getMessage}"
                    )
                }
                .get
            (file.children should have).length(stmtCount)
            all(file.children) shouldBe a[NopStmt]
            // Known provenance keys still read; unknown ones ignored.
            file.provenance.parserBackend shouldBe Some("nikic/php-parser@5.8.0")
            file.provenance.generatorVersion shouldBe Some("2.0.0")
          }
      }
  }

end ContractAdditivityTests
