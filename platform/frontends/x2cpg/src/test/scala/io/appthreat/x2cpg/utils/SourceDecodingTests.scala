package io.appthreat.x2cpg.utils

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.charset.{Charset, StandardCharsets}

class SourceDecodingTests extends AnyWordSpec with Matchers:

  private val text   = "// héllo wörld\nx = \"café\" 𝑥\n"
  private val latin1 = Charset.forName("ISO-8859-1")

  "SourceDecoding" should {
      "follow a byte-order mark, which is not part of the text" in {
          val boms = Seq(
            Array(0xef, 0xbb, 0xbf).map(_.toByte) ++ text.getBytes(StandardCharsets.UTF_8),
            Array(0xfe, 0xff).map(_.toByte) ++ text.getBytes(StandardCharsets.UTF_16BE),
            Array(0xff, 0xfe).map(_.toByte) ++ text.getBytes(StandardCharsets.UTF_16LE),
            Array(0xff, 0xfe, 0, 0).map(_.toByte) ++ text.getBytes(Charset.forName("UTF-32LE"))
          )
          boms.map(b => SourceDecoding.decode(b)).map(d => (d.text, d.hadBom)) shouldBe
              Seq.fill(4)((text, true))
      }

      "read valid UTF-8 as UTF-8" in {
          val decoded = SourceDecoding.decode(text.getBytes(StandardCharsets.UTF_8))
          decoded.text shouldBe text
          decoded.charset shouldBe StandardCharsets.UTF_8
      }

      "keep every byte of a file that is not UTF-8 as one character" in {
          val legacy  = "x = \"café\"\n"
          val decoded = SourceDecoding.decode(legacy.getBytes(latin1))
          decoded.text shouldBe legacy
          decoded.charset shouldBe SourceDecoding.Fallback
      }

      "prefer a declared charset to a guess" in {
          val sjis = Charset.forName("Shift_JIS")
          SourceDecoding.decode("s = \"日本\"".getBytes(sjis), Some(sjis)).text shouldBe "s = \"日本\""
      }
  }

  "escaped names" should {
      "be found with their spelling and decoded" in {
          val bs = "\\"
          UnicodeSkeleton.escapedSpelling(s"o.${bs}u0072un(x)", "run") shouldBe Some(
            s"${bs}u0072un"
          )
          UnicodeSkeleton.escapedSpelling(s"var ${bs}u{61}b = 1", "ab") shouldBe Some(
            s"${bs}u{61}b"
          )
          UnicodeSkeleton.escapedSpelling("run(x)", "run") shouldBe None
          UnicodeSkeleton.decodeEscapes(s"${bs}uu0041${bs}u{1D465}") shouldBe "A𝑥"
      }
  }
end SourceDecodingTests
