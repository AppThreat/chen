package io.appthreat.x2cpg.utils

import java.nio.ByteBuffer
import java.nio.charset.{CharacterCodingException, Charset, CodingErrorAction, StandardCharsets}
import java.nio.file.{Files, Path}
import scala.util.Try

/** The text of a source file whose encoding the language leaves to the file or the build:
  *   - a byte-order mark decides first (UTF-8, UTF-16 or UTF-32), and is not part of the text;
  *   - else the charset the file or its build declares (a Maven `project.build.sourceEncoding`);
  *   - else UTF-8 when the bytes are valid UTF-8;
  *   - else windows-1252, the encoding of most legacy sources that are not UTF-8: every byte stays
  *     one character, where UTF-8 would turn each into a U+FFFD.
  *
  * Python declares its own encoding (PEP 263, see pysrc2cpg's PythonSourceFile), and the Ruby, PHP
  * and JavaScript parsers read the files themselves.
  */
object SourceDecoding:

  final case class Decoded(text: String, charset: Charset, hadBom: Boolean)

  val Fallback: Charset = Charset.forName("windows-1252")

  private val Utf32Be = Try(Charset.forName("UTF-32BE")).toOption
  private val Utf32Le = Try(Charset.forName("UTF-32LE")).toOption

  /** The charset a byte-order mark at the start of `bytes` names, and the mark's length. */
  def bom(bytes: Array[Byte]): Option[(Charset, Int)] =
    def at(i: Int): Int = if i < bytes.length then bytes(i) & 0xff else -1
    (at(0), at(1), at(2), at(3)) match
      case (0xef, 0xbb, 0xbf, _)    => Some(StandardCharsets.UTF_8 -> 3)
      case (0x00, 0x00, 0xfe, 0xff) => Utf32Be.map(_ -> 4)
      case (0xff, 0xfe, 0x00, 0x00) => Utf32Le.map(_ -> 4)
      case (0xfe, 0xff, _, _)       => Some(StandardCharsets.UTF_16BE -> 2)
      case (0xff, 0xfe, _, _)       => Some(StandardCharsets.UTF_16LE -> 2)
      case _                        => None

  def decode(bytes: Array[Byte], declared: Option[Charset] = None): Decoded =
      bom(bytes) match
        case Some((charset, length)) =>
            Decoded(lenient(bytes, length, charset), charset, hadBom = true)
        case None =>
            declared match
              case Some(charset) => Decoded(lenient(bytes, 0, charset), charset, hadBom = false)
              case None =>
                  strictUtf8(bytes) match
                    case Some(text) => Decoded(text, StandardCharsets.UTF_8, hadBom = false)
                    case None => Decoded(lenient(bytes, 0, Fallback), Fallback, hadBom = false)

  def read(path: Path, declared: Option[Charset] = None): Decoded =
      decode(Files.readAllBytes(path), declared)

  /** A charset by name, if the JVM has it (`ISO-8859-1`, `Cp1252`, `Shift_JIS`). */
  def charsetNamed(name: String): Option[Charset] =
      Try(Charset.forName(name.trim)).toOption

  private def strictUtf8(bytes: Array[Byte]): Option[String] =
      try
        Some(
          StandardCharsets.UTF_8.newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bytes))
              .toString
        )
      catch case _: CharacterCodingException => None

  private def lenient(bytes: Array[Byte], offset: Int, charset: Charset): String =
      charset.newDecoder()
          .onMalformedInput(CodingErrorAction.REPLACE)
          .onUnmappableCharacter(CodingErrorAction.REPLACE)
          .decode(ByteBuffer.wrap(bytes, offset, bytes.length - offset))
          .toString
end SourceDecoding
