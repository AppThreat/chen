package io.appthreat.x2cpg.passes.taggers

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.util.regex.Pattern

class CdxPatternIndexTests extends AnyWordSpec with Matchers:
  import CdxPatternMatcher.*

  /** What the generated property steps do: exact for plain strings, `(?s)` full match otherwise. */
  private def reference(pattern: String, value: String): Boolean =
      if !io.shiftleft.codepropertygraph.generated.nodes.Misc.isRegex(pattern) then value == pattern
      else Pattern.compile(s"(?s)$pattern").matcher(value).matches()

  private val patterns = Seq(
    "django\\..*",
    "django\\.http.*",
    "rest_framework\\..*",
    "requests",
    "org.springframework.web.*",
    ".*",
    "a\\.b\\.c.*",
    "php\\\\Foo.*",
    "(app|config)/x.*"
  )
  private val values = Seq(
    "django.http.HttpRequest",
    "django",
    "django.httpx",
    "djangoXhttp",
    "requests",
    "requests.get",
    "org.springframework.web.Foo",
    "orgXspringframework.web",
    "a.b.c",
    "a.b.cd.e",
    "multi\nline",
    "php\\Foo\\Bar",
    "app/x.rb",
    ""
  )

  "CdxPatternMatcher" should {
      "classify literal-prefix patterns" in {
          CdxPatternMatcher("django\\..*") shouldBe Prefix("django.")
          CdxPatternMatcher("a\\.b.*") shouldBe Prefix("a.b")
          CdxPatternMatcher("requests") shouldBe Exact("requests")
          CdxPatternMatcher("org.spring.*") shouldBe a[Regex]
          CdxPatternMatcher("php\\\\Foo.*") shouldBe a[Regex]
      }

      "agree with regex semantics on every pattern and value" in {
          for p <- patterns; v <- values do
            withClue(s"pattern=$p value=$v: ") {
                CdxPatternMatcher(p).matches(v) shouldBe reference(p, v)
            }
      }
  }

  "CdxPatternIndex" should {
      "return the ids of exactly the matching patterns, in ascending order" in {
          val index = CdxPatternIndex(patterns.map(CdxPatternMatcher(_)).zipWithIndex)
          for v <- values do
            val expected = patterns.indices.filter(i => reference(patterns(i), v))
            withClue(s"value=$v: ")(index.matching(v) shouldBe expected)
      }

      "match nothing when empty" in {
          CdxPatternIndex(Nil).matching("anything") shouldBe empty
      }

      "return ids ascending across exact, prefix and regex buckets" in {
          // Ids deliberately inverted against bucket order: regex lowest, exact highest.
          val index = CdxPatternIndex(
            Seq(
              CdxPatternMatcher("dj.*go\\..*") -> 0,
              CdxPatternMatcher("django\\..*") -> 1,
              CdxPatternMatcher("django.http") -> 2
            )
          )
          index.matching("django.http") shouldBe IndexedSeq(0, 1, 2)
      }
  }
end CdxPatternIndexTests
