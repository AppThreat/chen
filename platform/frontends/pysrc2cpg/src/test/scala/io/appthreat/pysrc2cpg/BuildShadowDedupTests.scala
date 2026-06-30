package io.appthreat.pysrc2cpg

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Path

class BuildShadowDedupTests extends AnyWordSpec with Matchers:

  private val root = Path.of("/proj")
  private def abs(rel: String): Path = root.resolve(rel)
  private def dedup(rels: String*): Set[String] =
      Py2CpgOnFileSystem
          .dropShadowedBuildCopies(rels.map(abs), root)
          .map(p => root.relativize(p).toString)
          .toSet

  "dropShadowedBuildCopies" should {

    "drop a build/lib copy that shadows a real root source" in {
      dedup("django/utils/version.py", "build/lib/django/utils/version.py") shouldBe
          Set("django/utils/version.py")
    }

    "drop a dist copy that shadows a real src-layout source" in {
      dedup("src/pkg/core.py", "dist/pkg/core.py") shouldBe Set("src/pkg/core.py")
    }

    "match across src-layout on the real side and build/lib on the shadow side" in {
      dedup("src/pkg/core.py", "build/lib/pkg/core.py") shouldBe Set("src/pkg/core.py")
    }

    "keep build/dist files when they are the only copy (unzipped sdist/egg)" in {
      dedup("dist/mypkg-1.0/mypkg/__init__.py", "dist/mypkg-1.0/mypkg/api.py") shouldBe
          Set("dist/mypkg-1.0/mypkg/__init__.py", "dist/mypkg-1.0/mypkg/api.py")
    }

    "keep a build dir source that has no real-source counterpart" in {
      dedup("pkg/a.py", "build/lib/pkg/generated.py") shouldBe
          Set("pkg/a.py", "build/lib/pkg/generated.py")
    }

    "leave non-build trees untouched" in {
      dedup("a/b.py", "c/d.py") shouldBe Set("a/b.py", "c/d.py")
    }
  }
