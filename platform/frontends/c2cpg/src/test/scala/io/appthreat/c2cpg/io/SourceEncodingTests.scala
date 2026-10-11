package io.appthreat.c2cpg.io

import io.appthreat.c2cpg.{C2Cpg, Config}
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.charset.{Charset, StandardCharsets}
import java.nio.file.{Files, Path}

/** C sources are read by their byte-order mark (MSVC keeps UTF-16 sources), else as UTF-8, else as
  * windows-1252 - a Latin-1 string keeps its bytes.
  */
class SourceEncodingTests extends AnyWordSpec with Matchers:

  private val source =
      "// héllo wörld\nvoid foo(const char *a) {}\nvoid m(void) { const char *x = \"café\"; foo(x); }\n"

  private def parsed(bytes: Array[Byte])(check: io.shiftleft.codepropertygraph.Cpg => Unit) =
    val dir = Files.createTempDirectory("c2cpgEncoding")
    try
      Files.write(dir.resolve("main.c"), bytes)
      val out = Files.createTempFile("c2cpgEncoding", ".bin")
      val config = Config()
          .withInputPath(dir.toString)
          .withOutputPath(out.toString)
          .withFunctionBodies(true)
      val cpg = new C2Cpg().createCpg(config).get
      Files.deleteIfExists(out)
      try check(cpg)
      finally cpg.close()
    finally
      Files.walk(dir).sorted(java.util.Comparator.reverseOrder[Path]()).forEach(Files.delete(_))

  "C sources" should {
      "be read by their byte-order mark" in {
          val utf16 = Array(0xff, 0xfe).map(_.toByte) ++ source.getBytes(StandardCharsets.UTF_16LE)
          parsed(utf16) { cpg =>
            cpg.call.nameExact("foo").code.l shouldBe List("foo(x)")
            cpg.literal.code.l shouldBe List("\"café\"")
          }
      }

      "keep the bytes of a source that is not UTF-8" in {
          parsed(source.getBytes(Charset.forName("ISO-8859-1"))) { cpg =>
            cpg.call.nameExact("foo").code.l shouldBe List("foo(x)")
            cpg.literal.code.l shouldBe List("\"café\"")
          }
      }
  }
end SourceEncodingTests
