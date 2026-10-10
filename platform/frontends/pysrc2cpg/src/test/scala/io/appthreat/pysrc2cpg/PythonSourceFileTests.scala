package io.appthreat.pysrc2cpg

import better.files.File
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.charset.StandardCharsets

/** Source files are decoded the way CPython's tokenizer decodes them (PEP 263, PEP 3120), with
  * every expectation checked against CPython 3.15.0 (`ast.parse` of the same bytes).
  */
class PythonSourceFileTests extends AnyWordSpec with Matchers:

  private def bytes(parts: Any*): Array[Byte] =
      parts.toArray.flatMap {
          case s: String => s.getBytes(StandardCharsets.ISO_8859_1)
          case i: Int    => Array(i.toByte)
          case other     => fail(s"unexpected part $other")
      }

  private def utf8(s: String): Array[Byte] = s.getBytes(StandardCharsets.UTF_8)

  "PythonSourceFile.decode" should {

      "decode UTF-8 by default and keep characters beyond the BMP" in {
          // U+1D431 MATHEMATICAL BOLD SMALL X, U+1F600 GRINNING FACE
          PythonSourceFile.decode(utf8("\ud835\udc31 = '\ud83d\ude00'\n")) shouldBe
              "\ud835\udc31 = '\ud83d\ude00'"
      }

      "honour a coding cookie on the first line" in {
          // café = "naïve" in Latin-1
          val src = bytes("# -*- coding: latin-1 -*-\ncaf", 0xe9, " = \"na", 0xef, "ve\"\n")
          PythonSourceFile.decode(
            src
          ) shouldBe "# -*- coding: latin-1 -*-\ncaf\u00e9 = \"na\u00efve\""
      }

      "honour a cookie on the second line after a comment-only first line" in {
          // the Emacs/vim spellings and a Windows codepage: “quoted” in cp1252
          val src =
              bytes(
                "#!/usr/bin/env python\n# vim: set fileencoding=cp1252 :\nx = \"",
                0x93,
                "q",
                0x94,
                "\"\n"
              )
          PythonSourceFile.decode(src) should endWith("x = \"\u201cq\u201d\"")
      }

      "ignore a cookie on the second line when the first line is code" in {
          // CPython reads this file as UTF-8 (and rejects the latin-1 byte); chen replaces it
          val src = bytes("x = 1\n# coding: latin-1\ny = '", 0xe9, "'\n")
          PythonSourceFile.decode(src) should endWith("y = '\ufffd'")
      }

      "prefer a UTF-8 byte order mark and drop it" in {
          PythonSourceFile.decode(
            bytes(0xef, 0xbb, 0xbf) ++ utf8("x\u00e9 = 1\n")
          ) shouldBe "x\u00e9 = 1"
      }

      "normalise Python codec names to JVM charsets" in {
          for (name, expected) <- Seq(
              "latin-1"     -> "ISO-8859-1",
              "iso-latin-1" -> "ISO-8859-1",
              "Latin_1"     -> "ISO-8859-1",
              "utf8"        -> "UTF-8",
              "utf-8-sig"   -> "UTF-8",
              "cp1252"      -> "windows-1252",
              "euc_jp"      -> "EUC-JP",
              "shift_jis"   -> "Shift_JIS",
              "iso8859_15"  -> "ISO-8859-15",
              "koi8_r"      -> "KOI8-R",
              "ascii"       -> "US-ASCII"
            )
          do withClue(name)(PythonSourceFile.charsetFor(name).map(_.name) shouldBe Some(expected))
      }

      "fall back to UTF-8 for an encoding the JVM does not know" in {
          PythonSourceFile.decode(utf8("# coding: no-such-codec\nx\u00e9 = 1\n")) should endWith(
            "x\u00e9 = 1"
          )
      }

      "join CRLF and CR line breaks with LF and drop the final one" in {
          PythonSourceFile.decode(utf8("a = 1\r\nb = 2\rc = 3\n")) shouldBe "a = 1\nb = 2\nc = 3"
          PythonSourceFile.decode(utf8("a = 1\n\n")) shouldBe "a = 1\n"
          PythonSourceFile.decode(Array.emptyByteArray) shouldBe ""
      }
  }

  "Py2CpgOnFileSystem" should {

      "build the CPG of declared-encoding and supplementary-plane sources" in {
          File.usingTemporaryDirectory("chen-encodings-") { input =>
            (input / "legacy.py").writeByteArray(
              bytes("# -*- coding: latin-1 -*-\ncaf", 0xe9, " = 1\nprint(caf", 0xe9, ")\n")
            )
            // U+1D431 MATHEMATICAL BOLD SMALL X folds to x (NFKC), as in CPython
            (input / "math.py").writeByteArray(utf8("\ud835\udc31 = 2\nprint(x)\n"))
            val out = File.newTemporaryFile("chen-encodings-", ".odb")
            try
              val config = Py2CpgOnFileSystemConfig()
                  .withInputPath(input.pathAsString)
                  .withOutputPath(out.pathAsString)
                  .withCacheDir((input / ".cache").pathAsString)
              val cpg = new Py2CpgOnFileSystem().createCpg(config).get
              try
                cpg.identifier.nameExact("caf\u00e9").size shouldBe 2
                cpg.identifier.nameExact("x").size shouldBe 2
              finally cpg.close()
            finally out.delete(swallowIOExceptions = true)
          }
      }
  }
end PythonSourceFileTests
