package io.appthreat.x2cpg.utils

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{FileSystemException, Files, LinkOption, Path}
import scala.jdk.CollectionConverters.*

class AtomicWritesTests extends AnyWordSpec with Matchers:

  private val NoFollow: Array[LinkOption] = Array(LinkOption.NOFOLLOW_LINKS)

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

  private def entries(dir: Path): List[Path] =
      val stream = Files.list(dir)
      try stream.iterator().asScala.toList
      finally stream.close()

  /** The unpredictable temporaries all start with a dot and end in `.tmp`; none may survive a
    * completed write.
    */
  private def leftoverTemporaries(dir: Path): List[Path] =
      entries(dir).filter(p =>
          p.getFileName.toString.startsWith(".") && p.getFileName.toString.endsWith(".tmp")
      )

  "AtomicWrites.bytes" should {

      "replace a symbolic link at the final name instead of writing through it" in {
          val dir     = Files.createTempDirectory("atomic-writes")
          val outside = Files.createTempDirectory("atomic-target")
          val victim  = outside.resolve("victim.txt")
          Files.writeString(victim, "PRECIOUS")
          val target = dir.resolve("entry.bin")
          symlink(target, victim)

          AtomicWrites.bytes(target, "CONTENT".getBytes("UTF-8"))

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.isRegularFile(target, NoFollow: _*) shouldBe true
          Files.readString(target) shouldBe "CONTENT"
          leftoverTemporaries(dir) shouldBe empty
      }

      "leave a dangling link's target path uncreated" in {
          val dir     = Files.createTempDirectory("atomic-dangling")
          val nowhere = dir.resolve("nowhere").resolve("gone.txt")
          val target  = dir.resolve("entry.bin")
          symlink(target, nowhere)

          AtomicWrites.bytes(target, "CONTENT".getBytes("UTF-8"))

          Files.exists(nowhere) shouldBe false
          Files.isRegularFile(target, NoFollow: _*) shouldBe true
      }
  }

  "AtomicWrites.text" should {

      "replace a symbolic link at the final name instead of writing through it" in {
          val dir     = Files.createTempDirectory("atomic-text")
          val outside = Files.createTempDirectory("atomic-text-target")
          val victim  = outside.resolve("victim.json")
          Files.writeString(victim, "PRECIOUS")
          val target = dir.resolve("flowsummary-x.json")
          symlink(target, victim)

          AtomicWrites.text(target, "CONTENT")

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.readString(target) shouldBe "CONTENT"
          leftoverTemporaries(dir) shouldBe empty
      }
  }

  "AtomicWrites.copy" should {

      "copy onto a final name that is a symbolic link without touching the link's target" in {
          val dir     = Files.createTempDirectory("atomic-copy")
          val source  = dir.resolve("built.atom")
          Files.writeString(source, "BUILT")
          val outside = Files.createTempDirectory("atomic-copy-target")
          val victim  = outside.resolve("victim.atom")
          Files.writeString(victim, "PRECIOUS")
          val target = dir.resolve("cpg-x.atom")
          symlink(target, victim)

          AtomicWrites.copy(source, target)

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.readString(target) shouldBe "BUILT"
          leftoverTemporaries(dir) shouldBe empty
      }
  }

  "AtomicWrites.replace" should {

      "write the content a fill callback streams into the temporary" in {
          val dir    = Files.createTempDirectory("atomic-replace")
          val target = dir.resolve("streamed.json")

          AtomicWrites.replace(target) { tmp => Files.writeString(tmp, "STREAMED") }

          Files.readString(target) shouldBe "STREAMED"
          leftoverTemporaries(dir) shouldBe empty
      }

      "replace a symbolic link at the final name instead of writing through it" in {
          val dir     = Files.createTempDirectory("atomic-replace-link")
          val outside = Files.createTempDirectory("atomic-replace-target")
          val victim  = outside.resolve("victim.json")
          Files.writeString(victim, "PRECIOUS")
          val target = dir.resolve("streamed.json")
          symlink(target, victim)

          AtomicWrites.replace(target) { tmp => Files.writeString(tmp, "STREAMED") }

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.isRegularFile(target, NoFollow: _*) shouldBe true
          Files.readString(target) shouldBe "STREAMED"
          leftoverTemporaries(dir) shouldBe empty
      }

      "remove the temporary and leave the target alone when the fill throws" in {
          val dir    = Files.createTempDirectory("atomic-replace-fail")
          val target = dir.resolve("streamed.json")
          Files.writeString(target, "OLD")

          a[RuntimeException] should be thrownBy AtomicWrites.replace(target) { tmp =>
              Files.writeString(tmp, "PARTIAL")
              throw new RuntimeException("the stream broke")
          }

          Files.readString(target) shouldBe "OLD"
          leftoverTemporaries(dir) shouldBe empty
      }
  }

  "AtomicWrites.directory" should {

      "replace a final entry that is a symbolic link to a directory, leaving the target empty" in {
          val dir     = Files.createTempDirectory("atomic-dir")
          val outside = Files.createTempDirectory("atomic-dir-target")
          val entry   = dir.resolve("fp-entry")
          symlink(entry, outside)

          AtomicWrites.directory(entry) { tmp => Files.writeString(tmp.resolve("a.json"), "A") }

          Files.isDirectory(entry, NoFollow: _*) shouldBe true
          Files.readString(entry.resolve("a.json")) shouldBe "A"
          entries(outside) shouldBe empty
          leftoverTemporaries(dir) shouldBe empty
      }

      "replace a final entry that already holds an older tree" in {
          val dir   = Files.createTempDirectory("atomic-dir-replace")
          val entry = dir.resolve("fp-entry")
          Files.createDirectories(entry)
          Files.writeString(entry.resolve("stale.json"), "STALE")

          AtomicWrites.directory(entry) { tmp => Files.writeString(tmp.resolve("fresh.json"), "FRESH") }

          Files.readString(entry.resolve("fresh.json")) shouldBe "FRESH"
          Files.exists(entry.resolve("stale.json")) shouldBe false
      }
  }

  "AtomicWrites.checkCacheDirectory" should {

      "accept a directory that does not exist yet below an honest parent" in {
          val root = Files.createTempDirectory("check-honest")
          AtomicWrites.checkCacheDirectory(root.resolve(".chen")) shouldBe None
      }

      "accept an existing plain directory" in {
          val dir = Files.createTempDirectory("check-plain")
          AtomicWrites.checkCacheDirectory(dir) shouldBe None
      }

      "refuse a directory whose final component is a symbolic link, naming it" in {
          val root     = Files.createTempDirectory("check-link")
          val outside  = Files.createTempDirectory("check-link-target")
          val cacheDir = root.resolve(".chen")
          symlink(cacheDir, outside)

          AtomicWrites.checkCacheDirectory(cacheDir) shouldBe Some(s"$cacheDir is a symbolic link")
      }

      "refuse a path with a symbolic link below the deepest existing component" in {
          val root    = Files.createTempDirectory("check-link-mid")
          val outside = Files.createTempDirectory("check-link-mid-target")
          val link    = root.resolve("linkdir")
          symlink(link, outside)

          AtomicWrites.checkCacheDirectory(link.resolve(".chen")) shouldBe Some(
            s"$link is a symbolic link"
          )
      }

      "refuse a final component that exists but is a regular file" in {
          val root     = Files.createTempDirectory("check-file")
          val cacheDir = root.resolve(".chen")
          Files.writeString(cacheDir, "occupied")

          AtomicWrites.checkCacheDirectory(cacheDir) shouldBe Some(
            s"$cacheDir exists and is not a directory"
          )
      }

      "refuse a broken symbolic link at the final component" in {
          val root     = Files.createTempDirectory("check-broken")
          val cacheDir = root.resolve(".chen")
          symlink(cacheDir, root.resolve("does-not-exist"))

          AtomicWrites.checkCacheDirectory(cacheDir) shouldBe Some(s"$cacheDir is a symbolic link")
      }
  }
end AtomicWritesTests
