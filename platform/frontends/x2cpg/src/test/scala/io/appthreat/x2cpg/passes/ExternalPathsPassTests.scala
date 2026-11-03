package io.appthreat.x2cpg.passes

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{NewMethod, NewTypeDecl}
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The one meaning of `--external-paths` every source frontend shares: a match begins at a path
  * segment of the path relative to the input root, with either separator.
  */
class ExternalPathsPassTests extends AnyWordSpec with Matchers:

  "the path matcher" should {
      "name the vendored directory a path lies in" in {
          val m = ExternalPathMatcher("third_party/")
          m.vendoredPathOf("third_party/zlib/zlib.c") shouldBe Some("third_party")
          m.vendoredPathOf("main.c") shouldBe None
      }
      "anchor on a path segment: third_party is not not_third_party" in {
          val m = ExternalPathMatcher("third_party")
          m.vendoredPathOf("src/not_third_party/a.c") shouldBe None
          m.vendoredPathOf("not_third_party/a.c") shouldBe None
          m.vendoredPathOf("third_party/a.c") shouldBe Some("third_party")
          // a vendored directory below the root is still one
          m.vendoredPathOf("src/third_party/zlib/a.c") shouldBe Some("src/third_party")
      }
      "find a later segment when an earlier occurrence does not start a segment" in {
          ExternalPathMatcher("third_party").vendoredPathOf(
            "not_third_party/third_party/a.c"
          ) shouldBe Some("not_third_party/third_party")
      }
      "accept both separators" in {
          val m = ExternalPathMatcher("third_party/[^/]+")
          m.vendoredPathOf("third_party\\zlib\\zlib.c") shouldBe Some("third_party/zlib")
          m.vendoredPathOf("third_party/zlib/zlib.c") shouldBe Some("third_party/zlib")
          m.vendoredPathOf("src\\not_third_party\\zlib\\zlib.c") shouldBe None
      }
      "extend a match that ends inside a segment to the end of the segment" in {
          ExternalPathMatcher("stb_image").vendoredPathOf("include/stb_image.h") shouldBe
              Some("include/stb_image.h")
          ExternalPathMatcher("third_party/zl").vendoredPathOf(
            "third_party/zlib/zlib.c"
          ) shouldBe Some("third_party/zlib")
      }
      "let a capture group decide where the vendored directory ends" in {
          ExternalPathMatcher("(third_party/[^/]+)/src").vendoredPathOf(
            "third_party/zlib/src/a.c"
          ) shouldBe Some("third_party/zlib")
      }
      "mark nothing for an empty or invalid pattern" in {
          ExternalPathMatcher("").isEmpty shouldBe true
          ExternalPathMatcher("(").vendoredPathOf("(/a.c") shouldBe None
      }
  }

  "the pass" should {
      def graph(pattern: String): Cpg =
        val cpg     = Cpg.emptyCpg
        val builder = overflowdb.BatchedUpdate.DiffGraphBuilder()
        List("third_party/zlib/z.c", "src/not_third_party/n.c", "main.c").foreach { file =>
          builder.addNode(NewMethod().name(s"f_$file").filename(file).isExternal(false))
          builder.addNode(NewTypeDecl().name(s"t_$file").filename(file).isExternal(false))
        }
        overflowdb.BatchedUpdate.applyDiff(cpg.graph, builder)
        ExternalPathsPass.applyTo(cpg, pattern)
        cpg

      "mark the methods and types of matched files external, and only those" in {
          val cpg = graph("third_party")
          cpg.method.l.map(m => m.filename -> m.isExternal).toMap shouldBe Map(
            "third_party/zlib/z.c"    -> true,
            "src/not_third_party/n.c" -> false,
            "main.c"                  -> false
          )
          cpg.typeDecl.l.map(t => t.filename -> t.isExternal).toMap shouldBe Map(
            "third_party/zlib/z.c"    -> true,
            "src/not_third_party/n.c" -> false,
            "main.c"                  -> false
          )
      }
      "mark nothing without a pattern" in {
          graph("").method.isExternal.l should contain only false
      }
  }
end ExternalPathsPassTests
