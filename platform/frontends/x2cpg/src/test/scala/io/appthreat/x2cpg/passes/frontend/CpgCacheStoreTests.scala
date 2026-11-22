package io.appthreat.x2cpg.passes.frontend

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.ByteBuffer
import java.nio.file.StandardOpenOption.{CREATE_NEW, SPARSE, WRITE}
import java.nio.file.{FileSystemException, Files, LinkOption, Path}
import java.nio.file.attribute.FileTime
import scala.jdk.CollectionConverters.*
import scala.util.Using

class CpgCacheStoreTests extends AnyWordSpec with Matchers:

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

  private def project(files: (String, String)*): Path =
    val dir = Files.createTempDirectory("cpg-cache-proj")
    files.foreach { case (name, content) => Files.writeString(dir.resolve(name), content) }
    dir

  private val largeFileSize = Integer.MAX_VALUE.toLong + 1

  private def projectWithLargeFile(lastByte: Byte): Path =
    val dir = Files.createTempDirectory("cpg-cache-large")
    Using.resource(Files.newByteChannel(dir.resolve("big.pack"), CREATE_NEW, WRITE, SPARSE)) {
        channel =>
          channel.position(largeFileSize - 1)
          channel.write(ByteBuffer.wrap(Array(lastByte)))
    }
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
          val dir  = project("a.c" -> "int a;")
          val fp1  = CpgCacheStore.projectFingerprint(dir.toString, Seq("v=3.0.0"))
          val chen = Files.createDirectory(dir.resolve(AstCacheStore.CacheDirName))
          Files.writeString(chen.resolve("deadbeef.ast"), "cache bytes")
          val fp2 = CpgCacheStore.projectFingerprint(dir.toString, Seq("v=3.0.0"))
          fp1 shouldBe fp2
      }

      "change when a file over 2 GiB changes" in {
          val first  = projectWithLargeFile(1)
          val second = projectWithLargeFile(2)
          try
              CpgCacheStore.projectFingerprint(first.toString, Seq.empty) should not be
                  CpgCacheStore.projectFingerprint(second.toString, Seq.empty)
          finally Seq(first, second).foreach(dir => Files.delete(dir.resolve("big.pack")))
      }
  }

  private def write(dir: Path, rel: String, content: String): Path =
    val file = dir.resolve(rel)
    Files.createDirectories(file.getParent)
    Files.writeString(file, content)
    file

  private def fixedTime(file: Path, millis: Long): Unit =
      Files.setLastModifiedTime(file, FileTime.fromMillis(millis))

  "CpgCacheStore.projectFingerprint on a tree with version control and installed packages" should {

      "leave out .git, .hg and .svn entirely" in {
          val dir = project("a.js" -> "var a;")
          val fp1 = CpgCacheStore.projectFingerprint(dir.toString, Seq.empty)
          write(dir, ".git/objects/ab/cdef", "object")
          write(dir, ".hg/store/data", "data")
          write(dir, "sub/.svn/entries", "entries")
          CpgCacheStore.projectFingerprint(dir.toString, Seq.empty) shouldBe fp1
      }

      "describe node_modules files by path, size and time, and not by content" in {
          val dir  = project("a.js" -> "var a;")
          val dep  = write(dir, "node_modules/dep/index.js", "AAAA")
          val deep = write(dir, "pkg/node_modules/dep/index.js", "AAAA")
          Seq(dep, deep).foreach(fixedTime(_, 1_000_000L))
          def fp = CpgCacheStore.projectFingerprint(
            dir.toString,
            Seq.empty,
            metadataOnlyDirNames = Set("node_modules")
          )
          val before = fp

          // same size, same time, other bytes: not read, so the key stays
          Files.writeString(dep, "BBBB")
          fixedTime(dep, 1_000_000L)
          fp shouldBe before

          // a new time changes it, at the top and at a nested node_modules alike
          fixedTime(dep, 2_000_000L)
          val afterTouch = fp
          afterTouch should not be before
          fixedTime(deep, 3_000_000L)
          fp should not be afterTouch

          // a new size changes it
          val sized = fp
          Files.writeString(dep, "BBBBB")
          fixedTime(dep, 2_000_000L)
          fp should not be sized

          // a new file changes it
          val added = fp
          write(dir, "node_modules/other/index.js", "x")
          fp should not be added
      }

      "read node_modules by content when no metadata-only directory is named" in {
          val dir = project("a.js" -> "var a;")
          val dep = write(dir, "node_modules/dep/index.js", "AAAA")
          fixedTime(dep, 1_000_000L)
          val before = CpgCacheStore.projectFingerprint(dir.toString, Seq.empty)
          Files.writeString(dep, "BBBB")
          fixedTime(dep, 1_000_000L)
          CpgCacheStore.projectFingerprint(dir.toString, Seq.empty) should not be before
      }

      "still read project files by content when node_modules is described by metadata" in {
          val dir = project("a.js" -> "var a;")
          write(dir, "node_modules/dep/index.js", "x")
          def fp = CpgCacheStore.projectFingerprint(
            dir.toString,
            Seq.empty,
            metadataOnlyDirNames = Set("node_modules")
          )
          val before = fp
          val source = dir.resolve("a.js")
          val time   = Files.getLastModifiedTime(source).toMillis
          Files.writeString(source, "var b;")
          fixedTime(source, time)
          fp should not be before
      }

      "describe the files a predicate picks by metadata and drop the ones another picks" in {
          val dir     = project("a.js" -> "var a;")
          val ignored = write(dir, "docs/readme.js", "AAAA")
          val skipped = write(dir, "spec/x_spec.rb", "AAAA")
          fixedTime(ignored, 1_000_000L)
          def fp = CpgCacheStore.projectFingerprint(
            dir.toString,
            Seq.empty,
            skipPath = _.toString.contains("spec"),
            metadataOnlyPath = _.toString.contains("docs")
          )
          val before = fp
          Files.writeString(ignored, "BBBB")
          fixedTime(ignored, 1_000_000L)
          fp shouldBe before
          Files.writeString(skipped, "something else entirely")
          fp shouldBe before
          fixedTime(ignored, 4_000_000L)
          fp should not be before
      }

      "hand the predicates the path as the input is spelled" in {
          val dir  = project("a.js" -> "var a;")
          val seen = scala.collection.mutable.Set.empty[Path]
          CpgCacheStore.projectFingerprint(
            dir.toString,
            Seq.empty,
            skipPath =
                p =>
                  seen += p; false
          )
          seen.toSet shouldBe Set(dir.resolve("a.js"))
      }

      "not follow a symbolic link to a directory, and notice where it points" in {
          assume(!System.getProperty("os.name").toLowerCase.contains("win"))
          val dir      = project("a.js" -> "var a;")
          val outside1 = Files.createTempDirectory("fp-outside-1")
          val outside2 = Files.createTempDirectory("fp-outside-2")
          write(outside1, "big.js", "one")
          write(outside2, "big.js", "two")
          val link = dir.resolve("linked")
          Files.createSymbolicLink(link, outside1)
          val before = CpgCacheStore.projectFingerprint(dir.toString, Seq.empty)

          // content behind the link is not read
          Files.writeString(outside1.resolve("big.js"), "changed")
          CpgCacheStore.projectFingerprint(dir.toString, Seq.empty) shouldBe before

          // a link to another place is a different tree
          Files.delete(link)
          Files.createSymbolicLink(link, outside2)
          CpgCacheStore.projectFingerprint(dir.toString, Seq.empty) should not be before
      }

      "read the content behind a symbolic link to a file the project owns" in {
          assume(!System.getProperty("os.name").toLowerCase.contains("win"))
          val dir    = project("a.js" -> "var a;")
          val target = write(Files.createTempDirectory("fp-target"), "real.js", "one")
          Files.createSymbolicLink(dir.resolve("alias.js"), target)
          val before = CpgCacheStore.projectFingerprint(dir.toString, Seq.empty)
          Files.writeString(target, "two")
          CpgCacheStore.projectFingerprint(dir.toString, Seq.empty) should not be before
      }

      "be the same whatever order the file system lists the files in" in {
          val first = Files.createTempDirectory("fp-order-1")
          val other = Files.createTempDirectory("fp-order-2")
          Seq("b.js", "a.js", "c/d.js").foreach(write(first, _, "x"))
          Seq("c/d.js", "a.js", "b.js").foreach(write(other, _, "x"))
          Seq(first, other).foreach(d =>
              Seq("b.js", "a.js", "c/d.js").foreach(f => fixedTime(d.resolve(f), 1_000_000L))
          )
          val md = Set("c")
          CpgCacheStore.projectFingerprint(
            first.toString,
            Seq.empty,
            metadataOnlyDirNames = md
          ) shouldBe
              CpgCacheStore.projectFingerprint(other.toString, Seq.empty, metadataOnlyDirNames = md)
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
          try
            CacheControl.disable(CacheControl.Cpg)
            val store     = new CpgCacheStore(cacheDir)
            val builtAtom = Files.createTempFile("built", ".atom")
            Files.write(builtAtom, "ATOM".getBytes("UTF-8"))
            store.store("fp", builtAtom.toString)
            val out = Files.createTempFile("restored", ".atom")
            store.restore("fp", out.toString) shouldBe false
          finally CacheControl.enable(CacheControl.Cpg)
      }

      "replace a symbolic link at the entry's name instead of writing through it" in {
          val cacheDir = Files.createTempDirectory("cpg-cache-link")
          val outside  = Files.createTempDirectory("cpg-cache-link-target")
          val victim   = outside.resolve("victim.atom")
          Files.writeString(victim, "PRECIOUS")
          val entry = cacheDir.resolve("cpg-fp-1.atom")
          symlink(entry, victim)
          val builtAtom = Files.createTempFile("built", ".atom")
          Files.writeString(builtAtom, "BUILT")

          CacheControl.enable(CacheControl.Cpg)
          new CpgCacheStore(cacheDir.toString).store("fp-1", builtAtom.toString)

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS) shouldBe true
          Files.readString(entry) shouldBe "BUILT"
      }

      "treat an entry that is a symbolic link as a miss on restore" in {
          val cacheDir = Files.createTempDirectory("cpg-cache-link-miss")
          val outside  = Files.createTempDirectory("cpg-cache-link-miss-target")
          val secret   = outside.resolve("secret.atom")
          Files.writeString(secret, "SECRET")
          symlink(cacheDir.resolve("cpg-fp-1.atom"), secret)
          val out = Files.createTempFile("restored", ".atom")

          CacheControl.enable(CacheControl.Cpg)
          new CpgCacheStore(cacheDir.toString).restore("fp-1", out.toString) shouldBe false
          Files.readString(out) shouldBe "" // the link's target was not copied out
          Files.readString(secret) shouldBe "SECRET"
      }

      "be switched off when the cache directory position is a link, and still be used when the user configured it" in {
          val input   = Files.createTempDirectory("cpg-cache-chen")
          val outside = Files.createTempDirectory("cpg-cache-chen-target")
          val chen    = input.resolve(".chen")
          symlink(chen, outside)
          val builtAtom = Files.createTempFile("built", ".atom")
          Files.writeString(builtAtom, "BUILT")
          val out = Files.createTempFile("restored", ".atom")

          CacheControl.enable(CacheControl.Cpg)
          val refused = new CpgCacheStore(chen.toString)
          refused.store("fp-1", builtAtom.toString)
          refused.restore("fp-1", out.toString) shouldBe false
          Files.readString(out) shouldBe ""
          val stream = Files.list(outside)
          try stream.iterator().asScala.toList shouldBe empty
          finally stream.close()

          val trusted = new CpgCacheStore(chen.toString, trustedCacheDir = true)
          trusted.store("fp-1", builtAtom.toString)
          trusted.restore("fp-1", out.toString) shouldBe true
          Files.readString(out) shouldBe "BUILT"
      }
  }
end CpgCacheStoreTests
