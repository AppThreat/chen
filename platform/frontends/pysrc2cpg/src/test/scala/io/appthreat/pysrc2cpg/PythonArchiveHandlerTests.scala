package io.appthreat.pysrc2cpg

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.util.zip.{ZipEntry, ZipOutputStream}
import scala.jdk.CollectionConverters.*
import scala.util.Using

/** Task 12 Part A - the archive handler's security posture. Every adversarial case here is an
  * attack a malicious wheel/sdist can actually carry (crafted names, absolute paths, links out of
  * the tree, nesting/size bombs, truncation), and each asserts BOTH the loud failure and that
  * nothing was written outside the extraction root. The tar fixtures are written with a minimal
  * spec-conformant tar writer so the parser is exercised against real 512-byte headers, checksums
  * included - not against fixtures produced by the same code under test.
  */
class PythonArchiveHandlerTests extends AnyWordSpec with Matchers:

  private def tempDir(prefix: String): File = File.newTemporaryDirectory(prefix)

  private def zip(entries: (String, String)*): Array[Byte] =
    val bos = new ByteArrayOutputStream()
    Using.resource(new ZipOutputStream(bos)) { zos =>
        entries.foreach { case (name, content) =>
            zos.putNextEntry(ZipEntry(name))
            zos.write(content.getBytes(StandardCharsets.UTF_8))
            zos.closeEntry()
        }
    }
    bos.toByteArray

  private def gz(data: Array[Byte]): Array[Byte] =
    val bos = new ByteArrayOutputStream()
    Using.resource(new java.util.zip.GZIPOutputStream(bos))(_.write(data))
    bos.toByteArray

  // A minimal ustar writer: one 512-byte header per entry, data padded to 512.
  private def tarEntry(
    name: String,
    content: Array[Byte],
    typeFlag: Byte = '0',
    linkName: String =
        ""
  ): Array[Byte] =
    val header = Array.ofDim[Byte](512)
    def field(off: Int, len: Int, text: String): Unit =
        System.arraycopy(
          text.getBytes(StandardCharsets.UTF_8),
          0,
          header,
          off,
          math.min(text.length, len)
        )
    field(0, 100, name)
    field(100, 8, "0000644")                  // mode
    field(108, 8, "0000000")                  // uid
    field(116, 8, "0000000")                  // gid
    field(124, 12, f"${content.length}%011o") // size
    field(136, 12, f"${0}%011o")              // mtime
    // checksum placeholder: spaces, computed below
    (148 until 156).foreach(header(_) = ' '.toByte)
    header(156) = typeFlag
    field(157, 100, linkName)
    field(257, 6, "ustar")
    field(263, 2, "00")
    val checksum = header.map(b => b.toInt & 0xff).sum
    field(148, 6, f"$checksum%06o")
    val padded = content ++ Array.fill((512 - content.length % 512) % 512)(0.toByte)
    header ++ padded
  end tarEntry

  private def tar(entries: Array[Byte]*): Array[Byte] =
      entries.foldLeft(Array.emptyByteArray)(_ ++ _) ++
          Array.fill(1024)(0.toByte) // two zero end-blocks

  private def write(path: File, bytes: Array[Byte]): Unit =
      path.writeByteArray(bytes)

  private def extractOk(input: Path, tempRoot: File): Seq[PythonArchiveHandler.ExtractedArchive] =
      PythonArchiveHandler.extractArchives(input, tempRoot.path)

  "extractArchives" should {

      "unpack a wheel into a package root with dist-info beside it" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            write(
              dir / "flask-3.0.3-py3-none-any.whl",
              zip(
                "flask/__init__.py"              -> "X = 1\n",
                "flask/app.py"                   -> "Y = 2\n",
                "flask-3.0.3.dist-info/METADATA" -> "Metadata-Version: 2.1\nName: flask\n"
              )
            )
            val tmp       = tempDir("chen-extract-")
            val extracted = extractOk(dir.path, tmp)
            extracted should have size 1
            val children = Files.list(extracted.head.root).iterator().asScala.map(_
                .getFileName.toString).toSeq.sorted
            children shouldBe Seq("flask", "flask-3.0.3.dist-info")
            Files.readString(extracted.head.root.resolve("flask/app.py")) shouldBe "Y = 2\n"
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "unwrap the single <pkg>-<ver> root of an sdist tar.gz" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            val tgz = gz(tar(
              tarEntry(
                "mypkg-1.0/PKG-INFO",
                "Metadata-Version: 2.1\nName: mypkg\nVersion: 1.0\n".getBytes
              ),
              tarEntry("mypkg-1.0/src/mypkg/__init__.py", "A = 1\n".getBytes),
              tarEntry("mypkg-1.0/src/mypkg/core.py", "B = 2\n".getBytes)
            ))
            write(dir / "mypkg-1.0.tar.gz", tgz)
            val tmp       = tempDir("chen-extract-")
            val extracted = extractOk(dir.path, tmp)
            extracted should have size 1
            extracted.head.root.getFileName.toString shouldBe "mypkg-1.0"
            Files.readString(extracted.head.root.resolve("src/mypkg/core.py")) shouldBe "B = 2\n"
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "honor GNU long names ('L') in a tar.gz" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            val longName = "pkg/" + ("very/" * 40) + "deep.py"
            val tgz = gz(tar(
              tarEntry("././@LongLink", (longName + "\u0000").getBytes, typeFlag = 'L'),
              tarEntry("truncated-placeholder.py", "OK = 1\n".getBytes)
            ))
            write(dir / "long.tar.gz", tgz)
            val tmp = tempDir("chen-extract-")
            extractOk(dir.path, tmp)
            val extracted = tmp.listRecursively.filter(_.isRegularFile)
                .find(_.name == "deep.py").map(_.contentAsString)
            extracted shouldBe Some("OK = 1\n")
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "extract an egg with EGG-INFO and a pyz zipapp at the zip root" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            write(
              dir / "demo-1.0-py3.8.egg",
              zip(
                "demo/__init__.py"  -> "E = 1\n",
                "EGG-INFO/PKG-INFO" -> "Name: demo\n"
              )
            )
            write(dir / "app.pyz", zip("__main__.py" -> "print('hi')\n"))
            val tmp       = tempDir("chen-extract-")
            val extracted = extractOk(dir.path, tmp)
            extracted should have size 2
            extracted.map(e =>
                Files.exists(e.root.resolve("demo/__init__.py")) ||
                    Files.exists(e.root.resolve("__main__.py"))
            ).count(identity) shouldBe 2
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "refuse a zip-slip traversal entry and write nothing outside the temp root" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            write(
              dir / "evil.whl",
              zip(
                "../evil.txt"     -> "pwned\n",
                "pkg/__init__.py" -> "ok\n"
              )
            )
            val tmp    = tempDir("chen-extract-")
            val parent = File(tmp.path.getParent)
            val before = parent.listRecursively.map(_.pathAsString).toSet
            an[RuntimeException] should be thrownBy extractOk(dir.path, tmp)
            val after = parent.listRecursively.map(_.pathAsString).toSet
            // Nothing outside the temp root was created by the failed extraction.
            (after -- before).forall(_.startsWith(tmp.pathAsString)) shouldBe true
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "refuse an absolute zip entry path" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            write(dir / "evil.whl", zip("/etc/evil.txt" -> "pwned\n"))
            val tmp = tempDir("chen-extract-")
            an[RuntimeException] should be thrownBy extractOk(dir.path, tmp)
            Files.exists(tmp.path.getParent.resolve("etc/evil.txt")) shouldBe false
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "refuse a drive-absolute entry path" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            write(dir / "evil.whl", zip("C:/evil.txt" -> "pwned\n"))
            val tmp = tempDir("chen-extract-")
            an[RuntimeException] should be thrownBy extractOk(dir.path, tmp)
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "refuse a tar traversal entry name" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            val tgz = gz(tar(tarEntry("../../evil.py", "pwned\n".getBytes)))
            write(dir / "evil.tar.gz", tgz)
            val tmp = tempDir("chen-extract-")
            an[RuntimeException] should be thrownBy extractOk(dir.path, tmp)
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "refuse a tar symlink pointing outside the extraction root" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            val tgz = gz(tar(
              tarEntry("pkg/__init__.py", "ok\n".getBytes),
              tarEntry(
                "pkg/link",
                "../../../outside.txt".getBytes,
                typeFlag = '2',
                linkName = "../../../outside.txt"
              )
            ))
            write(dir / "evil.tar.gz", tgz)
            val tmp    = tempDir("chen-extract-")
            val parent = File(tmp.path.getParent)
            val before = parent.listRecursively.map(_.pathAsString).toSet
            an[RuntimeException] should be thrownBy extractOk(dir.path, tmp)
            val after = parent.listRecursively.map(_.pathAsString).toSet
            (after -- before).forall(_.startsWith(tmp.pathAsString)) shouldBe true
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "materialise an inside-root tar symlink as a link, not content" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            val tgz = gz(tar(
              tarEntry("pkg/__init__.py", "ok\n".getBytes),
              tarEntry("pkg/real.py", "VALUE = 42\n".getBytes),
              tarEntry("pkg/alias.py", Array.emptyByteArray, typeFlag = '2', linkName = "real.py")
            ))
            write(dir / "linked.tar.gz", tgz)
            val tmp       = tempDir("chen-extract-")
            val extracted = extractOk(dir.path, tmp)
            val link      = extracted.head.root.resolve("alias.py")
            Files.isSymbolicLink(link) shouldBe true
            Files.readString(link) shouldBe "VALUE = 42\n"
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "stop nested-archive recursion at the depth bound without failing" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            // matryoshka: each level is a zip containing the next level plus one .py
            var inner = zip("level/deepest.py" -> "X = 1\n")
            (1 to 14).foreach { i =>
              val bos = new ByteArrayOutputStream()
              Using.resource(new ZipOutputStream(bos)) { zos =>
                zos.putNextEntry(ZipEntry(s"level$i/mod$i.py"))
                zos.write("X = 1\n".getBytes(StandardCharsets.UTF_8))
                zos.closeEntry()
                zos.putNextEntry(ZipEntry(s"inner$i.zip"))
                zos.write(inner)
                zos.closeEntry()
              }
              inner = bos.toByteArray
            }
            write(dir / "matryoshka.zip", inner)
            val tmp = tempDir("chen-extract-")
            // Recursion is bounded, not fatal: the outer levels unpack, the deepest do not.
            noException should be thrownBy PythonArchiveHandler.extractArchives(dir.path, tmp.path)
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "fail loudly on a total-bytes bomb ceiling" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            // 1 MiB of zeros compresses to almost nothing; the ceiling is set far below it.
            val bomb = zip("big.py" -> ("0" * (1024 * 1024)))
            write(dir / "bomb.whl", bomb)
            val tmp = tempDir("chen-extract-")
            val ex = the[RuntimeException] thrownBy
                PythonArchiveHandler.extractArchivesWithLimits(
                  dir.path,
                  tmp.path,
                  maxTotalUncompressedBytes = 64L * 1024,
                  maxEntries = 200000,
                  maxDepth = 10
                )
            ex.getMessage should include("total-uncompressed-bytes ceiling")
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "fail loudly on an entry-count ceiling" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            write(
              dir / "many.whl",
              zip(
                (1 until 200).map(i => s"pkg/m$i.py" -> "X = 1\n")*
              )
            )
            val tmp = tempDir("chen-extract-")
            val ex = the[RuntimeException] thrownBy
                PythonArchiveHandler.extractArchivesWithLimits(
                  dir.path,
                  tmp.path,
                  maxTotalUncompressedBytes = 8L << 30,
                  maxEntries = 100,
                  maxDepth = 10
                )
            ex.getMessage should include("entry ceiling")
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "fail loudly on a truncated zip and a truncated tar.gz" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            val goodZip = zip("pkg/__init__.py" -> "X = 1\n")
            write(dir / "cut.whl", goodZip.take(goodZip.length / 2))
            val goodTar = gz(tar(tarEntry("pkg/__init__.py", "X = 1\n".getBytes)))
            write(dir / "cut.tar.gz", goodTar.take(goodTar.length / 2))
            val tmp = tempDir("chen-extract-")
            // A cut zip is either a ZipException from the JDK or our own guard - both loud.
            (the[Exception] thrownBy extractOk(dir.path, tmp)).getMessage should not be empty
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "extract an archive that contains no Python source without failing" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            write(dir / "data.whl", zip("assets/logo.png" -> "not really a png"))
            val tmp       = tempDir("chen-extract-")
            val extracted = extractOk(dir.path, tmp)
            extracted should have size 1
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "refuse an unsupported format loudly when it IS the input" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            val conda = dir / "pkg.conda"
            write(conda, "zip-wrapped-zstd".getBytes)
            val tmp = tempDir("chen-extract-")
            val ex  = the[RuntimeException] thrownBy extractOk(conda.path, tmp)
            ex.getMessage should include("Unsupported archive format")
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "ignore an unsupported archive that merely SITS in the input tree" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            // A project carrying a `.tar.xz` fixture or a `docs/samples.7z` has not asked for
            // either to be analysed, and refusing the whole run over an incidental file denies
            // analysis of an ordinary project. Only the input path itself is a request.
            write(dir / "fixture.tar.xz", "xz payload".getBytes)
            write(dir / "samples.7z", "7z payload".getBytes)
            write(dir / "real.whl", zip("pkg/__init__.py" -> "X = 1\n"))
            val tmp       = tempDir("chen-extract-")
            val extracted = extractOk(dir.path, tmp)
            extracted should have size 1
            extracted.head.archiveFile.getFileName.toString shouldBe "real.whl"
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "keep same-named archives in separate extraction directories" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            // Two distributions whose FILE NAMES coincide once sanitised previously resolved to
            // one destination and extracted into each other - two results pointing at one
            // silently merged tree, with whichever identity metadata survived.
            write(dir / "pkg+1.whl", zip("a/__init__.py" -> "A = 1\n"))
            write(dir / "pkg_1.whl", zip("b/__init__.py" -> "B = 1\n"))
            val tmp       = tempDir("chen-extract-")
            val extracted = extractOk(dir.path, tmp)
            extracted should have size 2
            extracted.map(_.root).distinct should have size 2
            // Neither tree acquired the other's package.
            extracted.foreach { e =>
              val tops = File(e.root).children.map(_.name).toSet
              tops should have size 1
            }
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "bound a single oversized entry MID-WRITE rather than after it" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            // The ceiling exists to stop a bomb reaching the disk. Charging a whole entry only
            // after copying it writes the entire payload first, which is the one case the guard
            // is for: one entry, unbounded size.
            write(dir / "bomb.whl", zip("big.py" -> ("0" * (4 * 1024 * 1024))))
            val tmp = tempDir("chen-extract-")
            the[RuntimeException] thrownBy
                PythonArchiveHandler.extractArchivesWithLimits(
                  dir.path,
                  tmp.path,
                  maxTotalUncompressedBytes = 128L * 1024,
                  maxEntries = 200000,
                  maxDepth = 10
                )
            // Nothing anywhere under the extraction root exceeds the ceiling by more than one
            // copy buffer - proof the write stopped mid-entry instead of completing.
            val written = File(tmp.path).listRecursively.filter(_.isRegularFile).map(_.size).toSeq
            written.foreach(_ should be <= (128L * 1024 + (1 << 16)))
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "refuse an oversized tar long-name entry before allocating for it" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            // The 'L' payload size is an attacker-controlled header field that becomes an array
            // length. Unbounded, a declared 2 GiB allocates 2 GiB (or overflows Int into a
            // NegativeArraySizeException) before any byte ceiling could react.
            val hugeName = "x" * (256 * 1024)
            write(
              dir / "evil.tar.gz",
              gz(
                tar(
                  tarEntry("././@LongLink", hugeName.getBytes, typeFlag = 'L'),
                  tarEntry("short.py", "X = 1\n".getBytes)
                )
              )
            )
            val tmp = tempDir("chen-extract-")
            val ex  = the[RuntimeException] thrownBy extractOk(dir.path, tmp)
            ex.getMessage should include("metadata entry")
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "accept a tar header whose checksum was written as a signed byte sum" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            // A historic family of tar writers sums header bytes as SIGNED chars. Such an
            // archive is valid, and rejecting it failed the whole analysis of a legitimate
            // sdist over a byte-signedness convention. A high-bit byte in the name is what
            // makes the two sums differ.
            val nonAscii = "pkg/café.py"
            val entry    = tarEntry(nonAscii, "X = 1\n".getBytes)
            val signed =
                (0 until 512).map(i => if i >= 148 && i < 156 then 32 else entry(i).toInt).sum
            val reSigned = entry.clone()
            val text     = f"$signed%06o"
            (148 until 156).foreach(reSigned(_) = ' '.toByte)
            System.arraycopy(
              text.getBytes(StandardCharsets.UTF_8),
              0,
              reSigned,
              148,
              math.min(text.length, 6)
            )
            write(dir / "signed.tar.gz", gz(tar(reSigned)))
            val tmp       = tempDir("chen-extract-")
            val extracted = extractOk(dir.path, tmp)
            extracted should have size 1
            tmp.delete(swallowIOExceptions = true)
          }
      }

      "treat pyz/pex as application archives and whl/egg/sdist as distributions" in {
          File.usingTemporaryDirectory("chen-arch-") { dir =>
            PythonArchiveHandler.isApplicationArchive((dir / "app.pyz").path) shouldBe true
            PythonArchiveHandler.isApplicationArchive((dir / "app.pex").path) shouldBe true
            PythonArchiveHandler.isApplicationArchive((dir / "f.whl").path) shouldBe false
            PythonArchiveHandler.isApplicationArchive((dir / "f.tar.gz").path) shouldBe false
          }
      }
  }
end PythonArchiveHandlerTests
