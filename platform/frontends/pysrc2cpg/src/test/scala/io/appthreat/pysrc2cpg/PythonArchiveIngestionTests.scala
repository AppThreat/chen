package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.util.zip.{ZipEntry, ZipOutputStream}
import scala.util.Using

/** Task 12 Part A, end to end: archives dropped into the project directory are unpacked, parsed
  * with their real package layout, attributed as dependency code (the placement rule), named by
  * their own package root, and tagged with the package identity their RECORD/METADATA states - no
  * SBOM anywhere in sight. Every assertion has its near-miss: the project's own file must not flip
  * external, the unshipped package must not appear, the shadowed build copy must not duplicate the
  * module.
  */
class PythonArchiveIngestionTests extends PySrc2CpgFixture(withOssDataflow = true):

  private def zipBytes(entries: (String, String)*): Array[Byte] =
    val bos = new ByteArrayOutputStream()
    Using.resource(new ZipOutputStream(bos)) { zos =>
        entries.foreach { case (name, content) =>
            zos.putNextEntry(ZipEntry(name))
            zos.write(content.getBytes(StandardCharsets.UTF_8))
            zos.closeEntry()
        }
    }
    bos.toByteArray

  /** A miniature but spec-shaped flask wheel: package + dist-info with METADATA and a RECORD that
    * lists the real file layout (the authoritative package -> module mapping).
    */
  private def flaskWheel: Array[Byte] = zipBytes(
    "flask/__init__.py" ->
        """from .app import Flask
        |""".stripMargin,
    "flask/app.py" ->
        """class Flask:
        |    def __init__(self, import_name):
        |        self.import_name = import_name
        |
        |    def run(self, host=None):
        |        return host
        |""".stripMargin,
    "flask-3.0.3.dist-info/METADATA" ->
        """Metadata-Version: 2.1
        |Name: Flask
        |Version: 3.0.3
        |""".stripMargin,
    "flask-3.0.3.dist-info/RECORD" ->
        """flask/__init__.py,sha256=x,10
        |flask/app.py,sha256=x,20
        |flask-3.0.3.dist-info/METADATA,,
        |""".stripMargin
  )

  private def writeArchives(dir: java.io.File): Unit =
      Files.write(dir.toPath.resolve("Flask-3.0.3-py3-none-any.whl"), flaskWheel)

  private val appUsingFlask =
      """from flask import Flask
        |app = Flask(__name__)
        |def boot():
        |    app.run("0.0.0.0")
        |""".stripMargin

  "a wheel dropped into the project directory" should {

      "be unpacked and parsed under its package-relative names" in {
          val cpg       = code(appUsingFlask, "app.py").withProjectSetup(writeArchives)
          val flaskCtor = cpg.method.fullNameExact("flask.app.Flask.__init__").l
          flaskCtor should not be empty
          // The FILE node names are package-relative, so import resolution joins them.
          cpg.file.name("flask/app.py").l should not be empty
      }

      "attribute the wheel's code as external dependency code, and only it" in {
          val cpg = code(appUsingFlask, "app.py").withProjectSetup(writeArchives)
          cpg.method.fullNameExact("flask.app.Flask.run").head.isExternal shouldBe true
          // The project's own method must not flip external - the near-miss the placement rule
          // exists for (getting it backwards changes every reachables count).
          val boot = cpg.method.name("boot").l
          boot should have size 1
          boot.head.isExternal shouldBe false
      }

      "tag the wheel's modules with the purl its RECORD/METADATA states, without any SBOM" in {
          val cpg = code(appUsingFlask, "app.py").withProjectSetup(writeArchives)
          val run = cpg.method.fullNameExact("flask.app.Flask.run").head
          run.tag.name.l should contain("pkg:pypi/flask@3.0.3")
          // The project's own code carries no purl.
          cpg.method.name("boot").head.tag.name.l should not contain "pkg:pypi/flask@3.0.3"
      }

      "let the engine descend into the unpacked library body (externality is not opacity)" in {
          // The discriminator: a library function whose BODY drops its argument. If the body
          // were opaque, the engine's permissive default would taint the call result anyway and
          // the flow would report; with the body in the graph the walk sees the argument never
          // reaches the return, and the flow must stop.
          def wheelWithDropper(dir: java.io.File): Unit =
              Files.write(
                dir.toPath.resolve("dropper-1.0-py3-none-any.whl"),
                zipBytes(
                  "dropper/__init__.py" -> "from .core import drop\n",
                  "dropper/core.py" ->
                      """def drop(arg):
                      |    return "constant"
                      |""".stripMargin,
                  "dropper-1.0.dist-info/METADATA" ->
                      """Metadata-Version: 2.1
                      |Name: dropper
                      |Version: 1.0
                      |""".stripMargin,
                  "dropper-1.0.dist-info/RECORD" ->
                      """dropper/__init__.py,sha256=x,10
                      |dropper/core.py,sha256=x,20
                      |dropper-1.0.dist-info/METADATA,,
                      |""".stripMargin
                )
              )
          val app =
              """from dropper import drop
                |def boot(user_input):
                |    out = drop(user_input)
                |    render(out)
                |""".stripMargin
          val cpg    = code(app, "app.py").withProjectSetup(wheelWithDropper)
          val sink   = cpg.call.nameExact("render").argument
          val source = cpg.method.nameExact("boot").parameter.nameExact("user_input").l
          source should not be empty
          sink.reachableByFlows(source).size shouldBe 0
      }

      "not ingest a name that collides with the project's own file (project wins)" in {
          val cpg = code("def boot():\n    return 1\n", "flask/app.py")
              .withProjectSetup(writeArchives)
          // The project's flask/app.py wins; the wheel's copy is skipped, so there is exactly
          // ONE Flask.__init__-era module for that file - the project's boot.
          val boots = cpg.method.name("boot").l
          boots should have size 1
          boots.head.filename shouldBe "flask/app.py"
          boots.head.isExternal shouldBe false
          // And the wheel's other file still arrived.
          cpg.file.name("flask/__init__.py").l should not be empty
      }

      "attribute a SINGLE-MODULE wheel, whose RECORD top-level entry is the file itself" in {
          // `typing_extensions.py` sits at the wheel root, so RECORD's leading path segment IS
          // the file name. Keeping the `.py` on it produced the import name
          // `typing_extensions.py`, which matches no module - so the purl was simply never
          // applied, and the loss was invisible because nothing errored.
          //
          // The distribution name also exercises PEP 503 normalisation: purl requires
          // `typing-extensions`, and lowercasing alone leaves `typing_extensions`, a purl that
          // compares unequal to every SBOM and advisory feed's spelling of the same package.
          def singleModuleWheel(dir: java.io.File): Unit =
              Files.write(
                dir.toPath.resolve("typing_extensions-4.12.2-py3-none-any.whl"),
                zipBytes(
                  "typing_extensions.py" -> "def override(fn):\n    return fn\n",
                  "typing_extensions-4.12.2.dist-info/METADATA" ->
                      """Metadata-Version: 2.1
                      |Name: typing_extensions
                      |Version: 4.12.2
                      |""".stripMargin,
                  "typing_extensions-4.12.2.dist-info/RECORD" ->
                      """typing_extensions.py,sha256=x,10
                      |typing_extensions-4.12.2.dist-info/METADATA,,
                      |""".stripMargin
                )
              )
          val cpg = code("from typing_extensions import override\n", "app.py")
              .withProjectSetup(singleModuleWheel)
          val override_ = cpg.method.fullNameExact("typing_extensions.override").l
          override_ should not be empty
          override_.head.tag.name.l should contain("pkg:pypi/typing-extensions@4.12.2")
      }
  }

  "an sdist dropped into the project directory" should {

      "drop the build/lib shadow copy its layout contains" in {
          // An sdist-style tree: src/mypkg/mod.py plus the build/lib shadow of the same module.
          // dropShadowedBuildCopies (per extraction root) keeps exactly one.
          def sdistFiles(dir: java.io.File): Unit =
            val tgz = gzip(tarBytes(
              tarEntry("mypkg-1.0/PKG-INFO", "Metadata-Version: 2.1\nName: mypkg\nVersion: 1.0\n"),
              tarEntry("mypkg-1.0/src/mypkg/__init__.py", "A = 1\n"),
              tarEntry("mypkg-1.0/src/mypkg/mod.py", "def used():\n    return 2\n"),
              tarEntry("mypkg-1.0/build/lib/mypkg/mod.py", "def used():\n    return 2\n")
            ))
            Files.write(dir.toPath.resolve("mypkg-1.0.tar.gz"), tgz)

          val cpg = code("from mypkg import used\n", "app.py").withProjectSetup(sdistFiles)
          // One module, not two: the shadow copy is dropped because src/ provides it.
          val useds = cpg.method.name("used").l
          useds should have size 1
          useds.head.filename shouldBe "src/mypkg/mod.py"
          // and the identity came from the sdist's PKG-INFO.
          useds.head.tag.name.l should contain("pkg:pypi/mypkg@1.0")
      }
  }

  "a pyz zipapp dropped into the project directory" should {

      "be analysed as application code, not dependency code" in {
          def pyz(dir: java.io.File): Unit =
              Files.write(
                dir.toPath.resolve("tool.pyz"),
                zipBytes(
                  "__main__.py"         -> "def main():\n    return 3\n",
                  "helpers/__init__.py" -> "H = 1\n"
                )
              )
          val cpg  = code("x = 1\n", "app.py").withProjectSetup(pyz)
          val main = cpg.method.fullNameExact("__main__.main").l
          main should not be empty
          // zipapps are programs the user placed there: internal, by the placement rule.
          main.head.isExternal shouldBe false
      }
  }

  "a wheel given as the input path itself" should {

      "be analysed as the code under analysis (internal, not a dependency)" in {
          val dir = Files.createTempDirectory("chen-input-whl-")
          val out = Files.createTempFile("chen-input-whl-", ".odb")
          try
            val whl = dir.resolve("Flask-3.0.3-py3-none-any.whl")
            Files.write(whl, flaskWheel)
            new Py2CpgOnFileSystem().createCpg(
              Py2CpgOnFileSystemConfig()
                  .withInputPath(whl.toString)
                  .withOutputPath(out.toString)
            ) match
              case scala.util.Success(cpg) =>
                  try
                    val run = cpg.method.fullNameExact("flask.app.Flask.run").l
                    run should not be empty
                    // The input archive is the analysed code: internal.
                    run.head.isExternal shouldBe false
                  finally cpg.close()
              case scala.util.Failure(e) => fail(s"createCpg failed: $e")
          finally
            Files.walk(dir).sorted(java.util.Comparator.reverseOrder()).forEach(_.toFile.delete())
            Files.deleteIfExists(out)
      }
  }

  // Minimal tar writer for the sdist fixture (kept local so this suite is self-contained).
  private def tarEntry(name: String, content: String): Array[Byte] =
    val data   = content.getBytes(StandardCharsets.UTF_8)
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
    field(100, 8, "0000644")
    field(108, 8, "0000000")
    field(116, 8, "0000000")
    field(124, 12, f"${data.length}%011o")
    field(136, 12, "00000000000")
    (148 until 156).foreach(header(_) = ' '.toByte)
    header(156) = '0'
    field(257, 6, "ustar")
    field(263, 2, "00")
    val checksum = header.map(b => b.toInt & 0xff).sum
    field(148, 6, f"$checksum%06o")
    header ++ data ++ Array.fill((512 - data.length % 512) % 512)(0.toByte)
  end tarEntry

  private def tarBytes(entries: Array[Byte]*): Array[Byte] =
      entries.foldLeft(Array.emptyByteArray)(_ ++ _) ++ Array.fill(1024)(0.toByte)

  private def gzip(data: Array[Byte]): Array[Byte] =
    val bos = new ByteArrayOutputStream()
    Using.resource(new java.util.zip.GZIPOutputStream(bos))(_.write(data))
    bos.toByteArray
end PythonArchiveIngestionTests
