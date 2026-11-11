package io.appthreat.x2cpg.passes.frontend

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Path}

class ExternalParseCacheTests extends AnyWordSpec with Matchers:

  private def outDirWith(files: (String, String)*): Path =
    val dir = Files.createTempDirectory("parse-out")
    files.foreach { case (rel, content) =>
        val p = dir.resolve(rel)
        Option(p.getParent).foreach(Files.createDirectories(_))
        Files.writeString(p, content)
    }
    dir

  "ExternalParseCache" should {

      "store an output directory and restore it on a fingerprint hit" in {
          val cacheDir = Files.createTempDirectory("parse-cache").toString
          CacheControl.enable(CacheControl.Astgen)
          val cache = new ExternalParseCache(cacheDir, CacheControl.Astgen)

          val produced = outDirWith("a.json" -> "AAA", "nested/b.json" -> "BBB")
          cache.store("fp-1", produced)

          val restored = Files.createTempDirectory("parse-restored")
          cache.restore("fp-1", restored) shouldBe true
          Files.readString(restored.resolve("a.json")) shouldBe "AAA"
          Files.readString(restored.resolve("nested/b.json")) shouldBe "BBB"

          // a different fingerprint misses
          val other = Files.createTempDirectory("parse-restored-2")
          cache.restore("fp-2", other) shouldBe false
      }

      "neither store nor restore when its cache kind is disabled" in {
          val cacheDir = Files.createTempDirectory("parse-cache-disabled").toString
          try
            CacheControl.disable(CacheControl.Astgen)
            val cache    = new ExternalParseCache(cacheDir, CacheControl.Astgen)
            val produced = outDirWith("a.json" -> "AAA")
            cache.store("fp", produced)
            cache.restore("fp", Files.createTempDirectory("parse-restored-3")) shouldBe false
          finally CacheControl.enable(CacheControl.Astgen)
      }

      "store but not restore while the parse report is collected" in {
          val cacheDir = Files.createTempDirectory("parse-cache-report").toString
          CacheControl.enable(CacheControl.Astgen)
          val cache = new ExternalParseCache(cacheDir, CacheControl.Astgen)
          System.setProperty("chen.parse.report", "unused")
          try
            cache.store("fp", outDirWith("a.json" -> "AAA"))
            cache.restore("fp", Files.createTempDirectory("parse-restored-4")) shouldBe false
          finally System.clearProperty("chen.parse.report")
          // the entry the report run stored serves the next run without the report
          cache.restore("fp", Files.createTempDirectory("parse-restored-5")) shouldBe true
      }
  }
end ExternalParseCacheTests
