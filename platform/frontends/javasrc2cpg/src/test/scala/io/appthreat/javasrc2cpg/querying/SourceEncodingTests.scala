package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.JavaSrc2Cpg
import io.appthreat.javasrc2cpg.util.SourceEncoding
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.charset.{Charset, StandardCharsets}
import java.nio.file.{Files, Path}

/** Sources are read in the charset their build compiles them with, or by their byte-order mark. */
class SourceEncodingTests extends AnyWordSpec with Matchers:

  private def withProject(files: (String, Array[Byte])*)(
    check: io.shiftleft.codepropertygraph.Cpg => Unit
  ) =
    val dir = Files.createTempDirectory("javasrc2cpgEncoding")
    try
      files.foreach { (name, bytes) =>
        val path = dir.resolve(name)
        Files.createDirectories(path.getParent)
        Files.write(path, bytes)
      }
      val cpg = new JavaSrc2Cpg().createCpg(dir.toString)(using JavaSrc2Cpg.DefaultConfig).get
      try check(cpg)
      finally cpg.close()
    finally
      Files.walk(dir).sorted(java.util.Comparator.reverseOrder[Path]()).forEach(Files.delete(_))

  private val source = "class E {\n  String m() { return \"café\"; }\n}\n"

  "a build's source encoding" should {
      "be read from Maven and Gradle builds" in {
          SourceEncoding.declaredBy(
            "<properties><project.build.sourceEncoding>ISO-8859-1</project.build.sourceEncoding>"
          ) shouldBe Some(Charset.forName("ISO-8859-1"))
          SourceEncoding.declaredBy("compileJava { options.encoding = 'windows-1252' }") shouldBe
              Some(Charset.forName("windows-1252"))
          SourceEncoding.declaredBy("<encoding>${project.encoding}</encoding>") shouldBe None
      }

      "decode the sources below it" in {
          val pom =
              "<project><properties><project.build.sourceEncoding>ISO-8859-1" +
                  "</project.build.sourceEncoding></properties></project>"
          withProject(
            "pom.xml"              -> pom.getBytes(StandardCharsets.US_ASCII),
            "src/main/java/E.java" -> source.getBytes(Charset.forName("ISO-8859-1"))
          ) { cpg =>
              cpg.literal.code.l shouldBe List("\"café\"")
          }
      }
  }

  "a byte-order mark" should {
      "decide a source's charset" in {
          val utf16 = Array(0xff, 0xfe).map(_.toByte) ++ source.getBytes(StandardCharsets.UTF_16LE)
          withProject("E.java" -> utf16) { cpg =>
            cpg.method.nameExact("m").size shouldBe 1
            cpg.literal.code.l shouldBe List("\"café\"")
          }
      }
  }
end SourceEncodingTests
