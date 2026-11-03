package io.appthreat.jssrc2cpg.utils

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import ujson.Value

import scala.io.Source

/** The normalizer against the table of examples shared with atom-parsetools' lib/typemap/canon.mjs:
  * every pair that names one type must normalize to one string, and every pair that does not must
  * stay apart.
  */
class TypeStringNormalizerTests extends AnyWordSpec with Matchers:

  private val rows: List[(String, String, String, Boolean)] =
    val in = getClass.getResourceAsStream("/typemap-normalization.json")
    val text =
        try Source.fromInputStream(in, "UTF-8").mkString
        finally in.close()
    ujson.read(text)("rows").arr.toList.map { (r: Value) =>
        (r("normalization").str, r("a").str, r("b").str, r("same").bool)
    }

  private val forms: List[(String, String)] =
    val in = getClass.getResourceAsStream("/typemap-normalization.json")
    val text =
        try Source.fromInputStream(in, "UTF-8").mkString
        finally in.close()
    ujson.read(text)("forms").arr.toList.map((r: Value) => (r("input").str, r("canonical").str))

  private val realStrings: List[String] =
    val in = getClass.getResourceAsStream("/typemap-real-strings.json")
    val text =
        try Source.fromInputStream(in, "UTF-8").mkString
        finally in.close()
    ujson.read(text)("strings").arr.toList.map(_.str)

  "the shared example table" should {
      "not be empty" in { rows.size should be > 10 }
  }

  "TypeStringNormalizer" should {
      rows.foreach { case (id, a, b, same) =>
          if same then
            s"[$id] write '$a' and '$b' the same" in {
                TypeStringNormalizer.normalize(a) shouldBe TypeStringNormalizer.normalize(b)
            }
          else
            s"[$id] keep '$a' and '$b' apart" in {
                TypeStringNormalizer.normalize(a) should not be TypeStringNormalizer.normalize(b)
            }
      }

      forms.foreach { case (input, canonical) =>
          s"write '$input' as '$canonical'" in {
              TypeStringNormalizer.normalize(input) shouldBe canonical
          }
      }

      // the only change with every normalization off: runs of white space outside string literals
      def collapsedOutsideLiterals(t: String): String =
          "(\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`(?:[^`\\\\]|\\\\.)*`)|\\s+".r
              .replaceAllIn(
                t,
                m => java.util.regex.Matcher.quoteReplacement(Option(m.group(1)).getOrElse(" "))
              )
              .trim

      "leave every real type string as written when no normalization is switched on" in {
          realStrings.size should be > 1000
          val respelled = realStrings.filter { t =>
              TypeStringNormalizer.normalize(
                t,
                unionOrder = false,
                objectOrder = false,
                quotes = false
              ) != collapsedOutsideLiterals(t)
          }
          respelled.take(5) shouldBe Nil
      }

      "be idempotent on every real type string" in {
          val unstable = realStrings.filter { t =>
            val once = TypeStringNormalizer.normalize(t)
            TypeStringNormalizer.normalize(once) != once
          }
          unstable.take(5) shouldBe Nil
      }

      "leave a string that needs no change as it is" in {
          for t <- Seq("string", "number", "Foo", "Array<string>", "() => void", "{ a: string; }")
          do
            TypeStringNormalizer.normalize(t) shouldBe t
      }

      "sort union members at any depth" in {
          TypeStringNormalizer.normalize("Promise<\"b\" | \"a\">") shouldBe "Promise<\"a\" | \"b\">"
          TypeStringNormalizer.normalize("{ k: 2 | 1; }") shouldBe "{ k: 1 | 2; }"
      }

      "keep the order of overload signatures and sort properties around them" in {
          val t = "{ z: number; (a: string): void; (a: number): void; b: string; }"
          TypeStringNormalizer.normalize(t) shouldBe
              "{ (a: string): void; (a: number): void; b: string; z: number; }"
      }

      "keep a function type's parameters in order" in {
          TypeStringNormalizer.normalize("(b: number, a: string) => void") shouldBe
              "(b: number, a: string) => void"
      }

      "turn single quotes into double quotes, keeping an escaped quote" in {
          TypeStringNormalizer.normalize("'it\\'s'") shouldBe "\"it's\""
          TypeStringNormalizer.normalize("'say \"hi\"'") shouldBe "\"say \\\"hi\\\"\""
      }

      "not fail on malformed input" in {
          for t <- Seq("", "(", ")", "{ a: ", "'unterminated", "<<>>", "a | ", "=>") do
            noException should be thrownBy TypeStringNormalizer.normalize(t)
      }
  }
end TypeStringNormalizerTests
