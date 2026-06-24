package io.appthreat.x2cpg.passes.frontend

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Path}

class CpgCacheStoreTests extends AnyWordSpec with Matchers {

    private def project(files: (String, String)*): Path =
      val dir = Files.createTempDirectory("cpg-cache-proj")
      files.foreach { case (name, content) => Files.writeString(dir.resolve(name), content) }
      dir

    "CpgCacheStore.projectFingerprint" should {

        "be stable for identical inputs and configuration" in {
            val dir = project("a.c" -> "int a;", "b.c" -> "int b;")
            val fp1 = CpgCacheStore.projectFingerprint(dir.toString, Seq("cfg=x", "v=3.0.0"))
            val fp2 = CpgCacheStore.projectFingerprint(dir.toString, Seq("cfg=x", "v=3.0.0"))
            fp1 shouldBe fp2
        }

        "change when a file's content changes" in {
            val dir = project("a.c" -> "int a;")
            val fp1 = CpgCacheStore.projectFingerprint(dir.toString, Seq("v=3.0.0"))
            Files.writeString(dir.resolve("a.c"), "int a; int c;")
            val fp2 = CpgCacheStore.projectFingerprint(dir.toString, Seq("v=3.0.0"))
            fp1 should not be fp2
        }

        "change when the configuration/version identity changes" in {
            val dir = project("a.c" -> "int a;")
            CpgCacheStore.projectFingerprint(dir.toString, Seq("v=3.0.0")) should not be
                CpgCacheStore.projectFingerprint(dir.toString, Seq("v=3.0.1"))
        }

        "ignore files inside the cache directory" in {
            val dir = project("a.c" -> "int a;")
            val fp1 = CpgCacheStore.projectFingerprint(dir.toString, Seq("v=3.0.0"))
            val chen = Files.createDirectory(dir.resolve(AstCacheStore.CacheDirName))
            Files.writeString(chen.resolve("deadbeef.ast"), "cache bytes")
            val fp2 = CpgCacheStore.projectFingerprint(dir.toString, Seq("v=3.0.0"))
            fp1 shouldBe fp2
        }
    }

    "CpgCacheStore" should {

        "store and restore a whole atom on a fingerprint hit, and miss on a different fingerprint" in {
            val cacheDir = Files.createTempDirectory("cpg-cache").toString
            CacheControl.enable(CacheControl.Cpg)
            val store = new CpgCacheStore(cacheDir)

            val builtAtom = Files.createTempFile("built", ".atom")
            Files.write(builtAtom, "ATOM-CONTENT".getBytes("UTF-8"))

            store.store("fp-1", builtAtom.toString)

            val out = Files.createTempFile("restored", ".atom")
            store.restore("fp-1", out.toString) shouldBe true
            Files.readString(out) shouldBe "ATOM-CONTENT"

            store.restore("fp-2", out.toString) shouldBe false
        }

        "neither store nor restore when the CPG cache is disabled" in {
            val cacheDir = Files.createTempDirectory("cpg-cache-disabled").toString
            try {
                CacheControl.disable(CacheControl.Cpg)
                val store     = new CpgCacheStore(cacheDir)
                val builtAtom = Files.createTempFile("built", ".atom")
                Files.write(builtAtom, "ATOM".getBytes("UTF-8"))
                store.store("fp", builtAtom.toString)
                val out = Files.createTempFile("restored", ".atom")
                store.restore("fp", out.toString) shouldBe false
            } finally CacheControl.enable(CacheControl.Cpg)
        }
    }
}
