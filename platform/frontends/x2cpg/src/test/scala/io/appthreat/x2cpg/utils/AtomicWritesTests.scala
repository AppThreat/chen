package io.appthreat.x2cpg.utils

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.attribute.{FileTime, PosixFilePermission}
import java.nio.file.{FileSystemException, Files, LinkOption, Path}
import scala.jdk.CollectionConverters.*
import scala.util.Try

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
          Files.isRegularFile(target, NoFollow*) shouldBe true
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
          Files.isRegularFile(target, NoFollow*) shouldBe true
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
          val dir    = Files.createTempDirectory("atomic-copy")
          val source = dir.resolve("built.atom")
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
          Files.isRegularFile(target, NoFollow*) shouldBe true
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

          Files.isDirectory(entry, NoFollow*) shouldBe true
          Files.readString(entry.resolve("a.json")) shouldBe "A"
          entries(outside) shouldBe empty
          leftoverTemporaries(dir) shouldBe empty
      }

      "replace a final entry that already holds an older tree" in {
          val dir   = Files.createTempDirectory("atomic-dir-replace")
          val entry = dir.resolve("fp-entry")
          Files.createDirectories(entry)
          Files.writeString(entry.resolve("stale.json"), "STALE")

          AtomicWrites.directory(entry) { tmp =>
              Files.writeString(tmp.resolve("fresh.json"), "FRESH")
          }

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

  "AtomicWrites.checkCacheDirectory with an anchor" should {

      "refuse a linked component even when the link's target already holds the deeper path" in {
          val input   = Files.createTempDirectory("check-anchored-input")
          val outside = Files.createTempDirectory("check-anchored-target")
          // the deepest component exists (through the link), which is what hid the link before
          Files.createDirectories(outside.resolve("astgen"))
          val chen = input.resolve(".chen")
          symlink(chen, outside)

          AtomicWrites.checkCacheDirectory(input.resolve(".chen").resolve("astgen"), input) shouldBe
              Some(s"$chen is a symbolic link")
      }

      "check every component below the anchor, existing or not" in {
          val input = Files.createTempDirectory("check-anchored-all")
          // nothing below the anchor exists yet, and none of it offends
          AtomicWrites.checkCacheDirectory(
            input.resolve(".chen").resolve("pydeps").resolve("pkg-1"),
            input
          ) shouldBe None

          // a regular file anywhere below the anchor offends, however deep
          Files.createDirectories(input.resolve(".chen").resolve("pydeps"))
          Files.writeString(input.resolve(".chen").resolve("pydeps").resolve("pkg-1"), "occupied")
          AtomicWrites.checkCacheDirectory(
            input.resolve(".chen").resolve("pydeps").resolve("pkg-1"),
            input
          ) shouldBe Some(
            s"${input.resolve(".chen").resolve("pydeps").resolve("pkg-1")} exists and is not a directory"
          )
      }

      "not check the anchor or anything above it" in {
          // the anchor itself is a link the user spelled; only what a checkout commits below it
          // is the run's to judge
          val input   = Files.createTempDirectory("check-anchored-real")
          val spelled = Files.createTempDirectory("check-anchored-spelled")
          val alias   = spelled.resolve("input")
          symlink(alias, input)

          AtomicWrites.checkCacheDirectory(alias.resolve(".chen"), alias) shouldBe None
      }

      "fall back to the unanchored walk for a directory not below the anchor" in {
          val anchor = Files.createTempDirectory("check-anchored-elsewhere")
          val own    = Files.createTempDirectory("check-anchored-own")
          // a directory of the run's own, beside the anchor: the deepest existing component is
          // the directory itself, no link in sight
          AtomicWrites.checkCacheDirectory(own.resolve(".chen"), anchor) shouldBe None
      }
  }
  "AtomicWrites temporaries" should {

      "give a written file the permissions a file created in place gets" in {
          val dir = Files.createTempDirectory("atomic-perms")
          assume(
            Files.getFileStore(dir).supportsFileAttributeView("posix"),
            "POSIX permissions only"
          )
          val reference = Files.createFile(dir.resolve("reference.txt"))
          val target    = dir.resolve("entry.bin")
          AtomicWrites.bytes(target, Array[Byte](1, 2, 3))
          Files.getPosixFilePermissions(target) shouldBe Files.getPosixFilePermissions(reference)
          // the umask of a test run leaves group or other read access on a plain new file, which
          // a temporary made by Files.createTempFile would have taken away
          Files.getPosixFilePermissions(reference).asScala.toSet should not be Set(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE
          )
      }

      "give a built directory the permissions a directory created in place gets" in {
          val dir = Files.createTempDirectory("atomic-dir-perms")
          assume(
            Files.getFileStore(dir).supportsFileAttributeView("posix"),
            "POSIX permissions only"
          )
          val reference = Files.createDirectory(dir.resolve("reference"))
          val target    = dir.resolve("entry")
          AtomicWrites.directory(target)(tmp => Files.writeString(tmp.resolve("a.json"), "{}"))
          Files.getPosixFilePermissions(target) shouldBe Files.getPosixFilePermissions(reference)
      }

      "write to a relative target name" in {
          val name   = s"atomic-relative-${System.nanoTime()}.txt"
          val target = Path.of(name)
          try
            AtomicWrites.text(target, "RELATIVE")
            Files.readString(target) shouldBe "RELATIVE"
          finally Files.deleteIfExists(target)
      }
  }

  "AtomicWrites.readRegular" should {

      "read a regular file" in {
          val file = Files.createTempFile("atomic-read", ".bin")
          Files.writeString(file, "BYTES")
          AtomicWrites.readRegular(file).map(String(_, "UTF-8")) shouldBe Some("BYTES")
      }

      "not read through a symbolic link" in {
          val dir    = Files.createTempDirectory("atomic-read-link")
          val victim = Files.writeString(dir.resolve("victim.txt"), "SECRET")
          val link   = dir.resolve("entry.ast")
          symlink(link, victim)
          AtomicWrites.readRegular(link) shouldBe None
      }

      "not read a directory or a missing file" in {
          val dir = Files.createTempDirectory("atomic-read-dir")
          AtomicWrites.readRegular(dir) shouldBe None
          AtomicWrites.readRegular(dir.resolve("missing")) shouldBe None
      }
  }

  "AtomicWrites.sweepStale" should {

      "remove an old leftover temporary and keep a fresh one, an entry and a linked leftover's target" in {
          val dir     = Files.createTempDirectory("atomic-sweep")
          val outside = Files.createTempDirectory("atomic-sweep-target")
          val victim  = Files.writeString(outside.resolve("victim.txt"), "PRECIOUS")
          val old     = Files.writeString(dir.resolve(".abc.ast.x1.tmp"), "old")
          val oldDir  = Files.createDirectory(dir.resolve(".fp.y2.tmp"))
          Files.writeString(oldDir.resolve("a.json"), "{}")
          val fresh = Files.writeString(dir.resolve(".abc.ast.z3.tmp"), "fresh")
          val entry = Files.writeString(dir.resolve("abc.ast"), "entry")
          val link  = dir.resolve(".link.w4.tmp")
          symlink(link, victim)
          val dayAndMore = FileTime.fromMillis(System.currentTimeMillis() - 25L * 60 * 60 * 1000)
          Files.setLastModifiedTime(old, dayAndMore)
          Files.setLastModifiedTime(oldDir, dayAndMore)
          Files.setLastModifiedTime(entry, dayAndMore)
          Try(
            Files.getFileAttributeView(
              link,
              classOf[java.nio.file.attribute.BasicFileAttributeView],
              LinkOption.NOFOLLOW_LINKS
            ).setTimes(dayAndMore, null, null)
          )

          AtomicWrites.sweepStale(dir)

          Files.exists(old, NoFollow*) shouldBe false
          Files.exists(oldDir, NoFollow*) shouldBe false
          Files.exists(fresh, NoFollow*) shouldBe true
          Files.exists(entry, NoFollow*) shouldBe true
          Files.readString(victim) shouldBe "PRECIOUS"
      }
  }

  "AtomicWrites.cacheDirRefusal" should {

      "take a trusted directory as given, even a linked one" in {
          val dir    = Files.createTempDirectory("atomic-trust")
          val target = Files.createDirectory(dir.resolve("real"))
          val link   = dir.resolve(".chen")
          symlink(link, target)
          AtomicWrites.cacheDirRefusal(link, trusted = true, Some(dir.toString)) shouldBe None
          AtomicWrites.cacheDirRefusal(link, trusted = false, Some(dir.toString)) should not be None
      }

      "refuse a position it cannot check" in {
          val refusal = AtomicWrites.cacheDirRefusal(
            Path.of("relative", ".chen"),
            trusted = false,
            Some("\u0000not a path")
          )
          refusal.exists(_.contains("could not be checked")) shouldBe true
      }
  }

end AtomicWritesTests
