package io.appthreat.php2atom.parser

import io.appthreat.php2atom.parser.Domain.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.util.Random

/** Property 7 (P7) — Node attribute round-trip (task 12.3; Validates: Requirement 3.1).
  *
  * Property statement: for an arbitrary non-negative `(startLine, startFilePos, kind)` triple
  * embedded in a nikic-shaped node's `attributes` object, decoding that node through
  * [[Domain.fromJson]] yields a [[Domain.PhpNode]] whose source-position attributes are preserved
  * exactly — `attributes.lineNumber == startLine`, `attributes.columnNumber == startFilePos`, and
  * `attributes.kind == kind` (see `Domain.PhpAttributes.apply`, which maps `attributes.startLine ->
  * lineNumber`, `attributes.startFilePos -> columnNumber`, `attributes.kind -> kind`).
  *
  * Implementation note: ScalaCheck is deliberately NOT used here. php2atom's `build.sbt` lists only
  * scalatest as a test dependency and there is no ScalaCheck (or scalatestplus) on the classpath.
  * Rather than add a new dependency, this test encodes the same universally-quantified property
  * with a hand-rolled generator: it draws many randomized triples via [[scala.util.Random]] and
  * asserts the round-trip invariant on each. The convention (scalatest `AnyWordSpec` + `Matchers`,
  * feeding JSON straight into `Domain.fromJson` so the test stays hermetic with no PHP runtime)
  * matches the sibling `ProvenanceAndFallbackTests` / `PropertyHookTests` in this package.
  *
  * Two decodable node shapes are exercised so the property is checked through real readers:
  *   - `Stmt_Nop` -> [[Domain.NopStmt]] (statement position)
  *   - `Scalar_Int` wrapped in a `Stmt_Expression` -> [[Domain.PhpInt]] (expression position,
  *     decoded via `readExpr`)
  */
class NodeAttributeRoundtripTests extends AnyWordSpec with Matchers:

  /** Deterministic seed keeps failures reproducible while still covering a wide input space. */
  private val rng        = new Random(0x50374ea7L)
  private val Iterations = 500

  /** Build a nikic-shaped `attributes` object carrying exactly the three round-tripped fields. */
  private def attributesJson(startLine: Int, startFilePos: Int, kind: Int): ujson.Obj =
      ujson.Obj("startLine" -> startLine, "startFilePos" -> startFilePos, "kind" -> kind)

  /** A `Stmt_Nop` node — decodes directly to [[NopStmt]] via `readStmt`. */
  private def nopNode(startLine: Int, startFilePos: Int, kind: Int): ujson.Obj =
      ujson.Obj(
        "nodeType"   -> "Stmt_Nop",
        "attributes" -> attributesJson(startLine, startFilePos, kind)
      )

  /** A `Scalar_Int` wrapped in a `Stmt_Expression` so it decodes to [[PhpInt]] via `readExpr`. The
    * attributes under test live on the inner `Scalar_Int`, which becomes the resulting expression.
    */
  private def wrappedIntNode(startLine: Int, startFilePos: Int, kind: Int): ujson.Obj =
    val scalar = ujson.Obj(
      "nodeType"   -> "Scalar_Int",
      "value"      -> 0,
      "attributes" -> attributesJson(startLine, startFilePos, kind)
    )
    ujson.Obj(
      "nodeType" -> "Stmt_Expression",
      "expr"     -> scalar,
      // Distinct outer attributes prove we assert on the inner node's attributes, not the wrapper's.
      "attributes" -> attributesJson(startLine + 7, startFilePos + 13, kind + 1)
    )

  /** Decode a single node (wrapped in the top-level statement array) and return the sole child. */
  private def decodeSingle(node: ujson.Obj): PhpNode =
    val file = Domain.fromJson(ujson.Arr(node))
    file.children match
      case single :: Nil => single
      case other         => fail(s"Expected exactly one decoded child but got: $other")

  private def assertRoundTrip(actual: PhpNode, startLine: Int, startFilePos: Int, kind: Int): Unit =
    actual.attributes.lineNumber.map(_.intValue) shouldBe Some(startLine)
    actual.attributes.columnNumber.map(_.intValue) shouldBe Some(startFilePos)
    actual.attributes.kind shouldBe Some(kind)

  /** Draw a non-negative int biased toward including 0 and large values as edge cases. */
  private def nonNegativeInt(): Int = rng.nextInt(Int.MaxValue)

  "Node attribute round-trip (P7)" should {

      "preserve startLine/startFilePos/kind for Stmt_Nop -> NopStmt (fixed edge values)" in {
          val edges = List(
            (0, 0, 0),
            (1, 0, 1),
            (Int.MaxValue, Int.MaxValue, Int.MaxValue),
            (0, Int.MaxValue, 0),
            (Int.MaxValue, 0, 42)
          )
          edges.foreach { case (line, pos, kind) =>
              val node = decodeSingle(nopNode(line, pos, kind))
              node shouldBe a[NopStmt]
              assertRoundTrip(node, line, pos, kind)
          }
      }

      "preserve startLine/startFilePos/kind for wrapped Scalar_Int -> PhpInt (fixed edge values)" in {
          val edges = List(
            (0, 0, 0),
            (1, 0, 1),
            (Int.MaxValue, Int.MaxValue, Int.MaxValue),
            (0, Int.MaxValue, 0),
            (Int.MaxValue, 0, 42)
          )
          edges.foreach { case (line, pos, kind) =>
              val node = decodeSingle(wrappedIntNode(line, pos, kind))
              node shouldBe a[PhpInt]
              assertRoundTrip(node, line, pos, kind)
          }
      }

      s"hold across $Iterations randomized non-negative triples for Stmt_Nop -> NopStmt" in {
          (1 to Iterations).foreach { _ =>
            val line = nonNegativeInt()
            val pos  = nonNegativeInt()
            val kind = nonNegativeInt()
            val node = decodeSingle(nopNode(line, pos, kind))
            node shouldBe a[NopStmt]
            assertRoundTrip(node, line, pos, kind)
          }
      }

      s"hold across $Iterations randomized non-negative triples for wrapped Scalar_Int -> PhpInt" in {
          (1 to Iterations).foreach { _ =>
            val line = nonNegativeInt()
            val pos  = nonNegativeInt()
            val kind = nonNegativeInt()
            val node = decodeSingle(wrappedIntNode(line, pos, kind))
            node shouldBe a[PhpInt]
            assertRoundTrip(node, line, pos, kind)
          }
      }
  }
end NodeAttributeRoundtripTests
