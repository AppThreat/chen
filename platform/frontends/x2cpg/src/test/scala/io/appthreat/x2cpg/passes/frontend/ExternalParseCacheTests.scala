package io.appthreat.x2cpg.passes.frontend

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{FileSystemException, Files, LinkOption, Path, Paths}
import scala.jdk.CollectionConverters.*

class ExternalParseCacheTests extends AnyWordSpec with Matchers:

  /** Creates a symbolic link at `link` pointing at `target`, skipping the test where the platform
    * refuses to create one.
    */
  private def symlink(link: Path, target: Path): Unit =
      try Files.createSymbolicLink(link, target)
      catch
        case e: UnsupportedOperationException =>
            assume(false, s"this platform cannot create symbolic links: ${e.getMessage}")
        case e: FileSystemException =>
            assume(false, s"this platform refused to create a symbolic link: ${e.getMessage}")

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

      "say whether it can be used, so a caller can skip the work a key needs" in {
          val cacheDir = Files.createTempDirectory("parse-cache-usable").toString
          try
            CacheControl.enable(CacheControl.Astgen)
            new ExternalParseCache(cacheDir, CacheControl.Astgen).isUsable shouldBe true
            // no directory to keep entries in
            new ExternalParseCache("", CacheControl.Astgen).isUsable shouldBe false
            CacheControl.disable(CacheControl.Astgen)
            new ExternalParseCache(cacheDir, CacheControl.Astgen).isUsable shouldBe false
          finally CacheControl.enable(CacheControl.Astgen)
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

      "replace a symbolic link at the entry directory's name instead of storing through it" in {
          val cacheDir = Files.createTempDirectory("parse-cache-entry-link")
          val outside  = Files.createTempDirectory("parse-cache-entry-target")
          CacheControl.enable(CacheControl.Astgen)
          val cache = new ExternalParseCache(cacheDir.toString, CacheControl.Astgen)
          val entry = cacheDir.resolve(CacheControl.Astgen).resolve("fp-1")
          Files.createDirectories(entry.getParent)
          symlink(entry, outside)

          cache.store("fp-1", outDirWith("a.json" -> "AAA"))

          Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS) shouldBe true
          Files.readString(entry.resolve("a.json")) shouldBe "AAA"
          val stream = Files.list(outside)
          try stream.iterator().asScala.toList shouldBe empty
          finally stream.close()
      }

      "treat an entry directory that is a symbolic link as a miss on restore" in {
          val cacheDir = Files.createTempDirectory("parse-cache-entry-miss")
          val outside  = Files.createTempDirectory("parse-cache-entry-miss-target")
          Files.writeString(outside.resolve("a.json"), "SECRET")
          CacheControl.enable(CacheControl.Astgen)
          val cache = new ExternalParseCache(cacheDir.toString, CacheControl.Astgen)
          val entry = cacheDir.resolve(CacheControl.Astgen).resolve("fp-1")
          Files.createDirectories(entry.getParent)
          symlink(entry, outside)

          val restored = Files.createTempDirectory("parse-restored-link")
          cache.restore("fp-1", restored) shouldBe false
          Files.readString(outside.resolve("a.json")) shouldBe "SECRET"
          val stream = Files.list(restored)
          try stream.iterator().asScala.toList shouldBe empty
          finally stream.close()
      }

      "not copy a symbolic link out of the parsed output, nor read its target, when storing" in {
          val cacheDir = Files.createTempDirectory("parse-cache-link-out")
          val outside  = Files.createTempDirectory("parse-cache-link-out-target")
          Files.writeString(outside.resolve("secret.json"), "SECRET")
          CacheControl.enable(CacheControl.Astgen)
          val produced = outDirWith("a.json" -> "AAA")
          symlink(produced.resolve("alias.json"), outside.resolve("secret.json"))
          // a link to a directory must not be descended into either
          val linkedDir = Files.createTempDirectory("parse-cache-link-out-dir")
          Files.writeString(linkedDir.resolve("deep.json"), "DEEP")
          symlink(produced.resolve("linkeddir"), linkedDir)

          new ExternalParseCache(cacheDir.toString, CacheControl.Astgen).store("fp-1", produced)

          val entry = cacheDir.resolve(CacheControl.Astgen).resolve("fp-1")
          Files.exists(entry.resolve("alias.json")) shouldBe false
          Files.exists(entry.resolve("linkeddir")) shouldBe false
          Files.readString(entry.resolve("a.json")) shouldBe "AAA"
      }

      "not copy a symbolic link out of a stored entry, nor read its target, when restoring" in {
          val cacheDir = Files.createTempDirectory("parse-cache-link-in").toString
          CacheControl.enable(CacheControl.Astgen)
          val cache = new ExternalParseCache(cacheDir, CacheControl.Astgen)
          cache.store("fp-1", outDirWith("a.json" -> "AAA"))

          // a committed link inside the stored entry, pointing outside the tree
          val outside = Files.createTempDirectory("parse-cache-link-in-target")
          Files.writeString(outside.resolve("secret.json"), "SECRET")
          val entry = Paths.get(cacheDir, CacheControl.Astgen, "fp-1")
          symlink(entry.resolve("alias.json"), outside.resolve("secret.json"))
          val linkedDir = Files.createTempDirectory("parse-cache-link-in-dir")
          Files.writeString(linkedDir.resolve("deep.json"), "DEEP")
          symlink(entry.resolve("linkeddir"), linkedDir)

          val restored = Files.createTempDirectory("parse-restored-link-in")
          cache.restore("fp-1", restored) shouldBe true
          Files.readString(restored.resolve("a.json")) shouldBe "AAA"
          Files.exists(restored.resolve("alias.json")) shouldBe false
          Files.exists(restored.resolve("linkeddir")) shouldBe false
          Files.readString(outside.resolve("secret.json")) shouldBe "SECRET"
          Files.readString(linkedDir.resolve("deep.json")) shouldBe "DEEP"
      }

      "be switched off when the cache directory position is a link, and still be used when the user configured it" in {
          val input   = Files.createTempDirectory("parse-cache-chen")
          val outside = Files.createTempDirectory("parse-cache-chen-target")
          val chen    = input.resolve(".chen")
          symlink(chen, outside)
          CacheControl.enable(CacheControl.Astgen)

          val refused = new ExternalParseCache(chen.toString, CacheControl.Astgen)
          refused.isUsable shouldBe false
          refused.store("fp-1", outDirWith("a.json" -> "AAA"))
          refused.restore("fp-1", Files.createTempDirectory("parse-restored-refused")) shouldBe false
          val stream = Files.list(outside)
          try stream.iterator().asScala.toList shouldBe empty
          finally stream.close()

          val trusted = new ExternalParseCache(chen.toString, CacheControl.Astgen, trustedCacheDir = true)
          trusted.isUsable shouldBe true
          trusted.store("fp-1", outDirWith("a.json" -> "AAA"))
          val restored = Files.createTempDirectory("parse-restored-trusted")
          trusted.restore("fp-1", restored) shouldBe true
          Files.readString(restored.resolve("a.json")) shouldBe "AAA"
      }

      "be switched off when the entry directory is a link inside a real cache directory" in {
          // a real .chen with its kind subdirectory committed as a link: the plain directory
          // above must not let the store read and write through the link
          val input   = Files.createTempDirectory("parse-cache-entrydir")
          val chen    = Files.createDirectories(input.resolve(".chen"))
          val outside = Files.createTempDirectory("parse-cache-entrydir-target")
          symlink(chen.resolve(CacheControl.Astgen), outside)
          CacheControl.enable(CacheControl.Astgen)

          val cache = new ExternalParseCache(chen.toString, CacheControl.Astgen)
          cache.isUsable shouldBe false

          // a run without the cache completes: storing is a no-op and restoring answers a miss
          cache.store("fp-1", outDirWith("a.json" -> "AAA"))
          cache.restore("fp-1", Files.createTempDirectory("parse-restored-entrydir")) shouldBe false

          val stream = Files.list(outside)
          try stream.iterator().asScala.toList shouldBe empty
          finally stream.close()
          val chenStream = Files.list(chen)
          try chenStream.iterator().asScala.map(_.getFileName.toString).toList shouldBe
              List(CacheControl.Astgen)
          finally chenStream.close()
      }

      "be switched off when a linked .chen's target already holds the kind directory" in {
          // `.chen` committed as a link, and the directory it points at already containing
          // `astgen/`: the entry directory then exists (through the link), which is what hid
          // the link from a walk that starts at the deepest existing component
          val input   = Files.createTempDirectory("parse-cache-anchored")
          val outside = Files.createTempDirectory("parse-cache-anchored-target")
          val kindDir = Files.createDirectories(outside.resolve(CacheControl.Astgen))
          Files.writeString(kindDir.resolve("left.json"), "LEFT")
          val chen = input.resolve(".chen")
          symlink(chen, outside)
          CacheControl.enable(CacheControl.Astgen)

          val cache =
              new ExternalParseCache(
                chen.toString,
                CacheControl.Astgen,
                cacheDirAnchor = Some(input.toString)
              )
          cache.isUsable shouldBe false

          // a run without the cache completes: storing is a no-op and restoring answers a miss
          cache.store("fp-1", outDirWith("a.json" -> "AAA"))
          cache.restore("fp-1", Files.createTempDirectory("parse-restored-anchored")) shouldBe false

          Files.readString(kindDir.resolve("left.json")) shouldBe "LEFT"
          val stream = Files.list(kindDir)
          try stream.iterator().asScala.map(_.getFileName.toString).toList shouldBe List("left.json")
          finally stream.close()
      }

      "never open the old predictable entry temporary name, a link there included" in {
          val cacheDir = Files.createTempDirectory("parse-cache-oldtmp")
          val entries  = Files.createDirectories(cacheDir.resolve(CacheControl.Astgen))
          val outside  = Files.createTempDirectory("parse-cache-oldtmp-target")
          Files.writeString(outside.resolve("left.json"), "PRECIOUS")
          // the entry temporary name earlier chen versions filled, committed as a link to a
          // directory: the old store opened that predictable name, its cleanup removing and
          // recreating whatever sat there (a walk does not follow a link at its start, so the
          // link went, not its target), and its tree copy read through links in both
          // directions; the store now never opens the name
          val oldTmp = entries.resolve("fp-1.tmp")
          symlink(oldTmp, outside)
          CacheControl.enable(CacheControl.Astgen)

          new ExternalParseCache(cacheDir.toString, CacheControl.Astgen).store("fp-1", outDirWith(
            "a.json" -> "AAA"
          ))

          Files.readString(outside.resolve("left.json")) shouldBe "PRECIOUS"
          Files.isSymbolicLink(oldTmp) shouldBe true // the name was never opened
          Files.isRegularFile(entries.resolve("fp-1").resolve("a.json")) shouldBe true
      }
  }
end ExternalParseCacheTests
