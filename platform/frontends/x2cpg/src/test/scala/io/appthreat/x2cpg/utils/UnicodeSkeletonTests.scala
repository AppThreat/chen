package io.appthreat.x2cpg.utils

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class UnicodeSkeletonTests extends AnyWordSpec with Matchers:

  "the skeleton" should {
      "be the same for a Latin name and its Cyrillic look-alike" in {
          // CYRILLIC SMALL LETTER ER (U+0440) and A (U+0430)
          UnicodeSkeleton.skeleton("раypal") shouldBe UnicodeSkeleton.skeleton("paypal")
      }
      "tell different names apart" in {
          UnicodeSkeleton.skeleton("value") should not be UnicodeSkeleton.skeleton("valve")
      }
      "also match ASCII look-alikes, which the tagger leaves alone" in {
          UnicodeSkeleton.skeleton("rn") shouldBe UnicodeSkeleton.skeleton("m")
          UnicodeSkeleton.isAscii("rn") shouldBe true
      }
  }

  "bidi controls" should {
      "be listed in order of first appearance" in {
          UnicodeSkeleton.bidiControlsIn("a‮b⁦c‮") shouldBe List("U+202E", "U+2066")
          UnicodeSkeleton.bidiControlsIn("plain") shouldBe empty
      }
  }
end UnicodeSkeletonTests
