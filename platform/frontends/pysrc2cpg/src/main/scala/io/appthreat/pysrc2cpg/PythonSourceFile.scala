package io.appthreat.pysrc2cpg

import java.nio.ByteBuffer
import java.nio.charset.{Charset, CodingErrorAction, StandardCharsets}
import java.nio.file.{Files, Path}
import scala.util.Try

/** Reads a Python source file the way CPython's tokenizer decodes it (PEP 263, PEP 3120).
  *
  * A UTF-8 byte order mark selects UTF-8. Otherwise an encoding declaration (`# -*- coding: latin-1
  * -*-`, `# vim: set fileencoding=cp1252 :`) on the first line, or on the second when the first is
  * blank or a comment, names the encoding; without one the source is UTF-8. Undecodable bytes
  * become U+FFFD instead of failing the file, and an encoding the JVM does not know falls back to
  * UTF-8.
  *
  * Line breaks (`\r\n`, `\r`, `\n`) are joined with `\n` and a final line break is dropped, as
  * reading the file line by line and joining the lines did before; characters beyond the Basic
  * Multilingual Plane are kept as surrogate pairs.
  */
object PythonSourceFile:

  // CPython's tokenize.cookie_re and blank_re, applied to a line decoded as Latin-1
  private val CodingCookie   = """^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)""".r.unanchored
  private val BlankOrComment = """^[ \t\f]*(?:[#\r\n].*|)$""".r
  private val Utf8Bom        = Array(0xef.toByte, 0xbb.toByte, 0xbf.toByte)

  // Python codec names with no JVM alias of the same spelling
  private val PythonCodecAliases = Map(
    "latin_1"     -> "ISO-8859-1",
    "latin1"      -> "ISO-8859-1",
    "iso_latin_1" -> "ISO-8859-1",
    "l1"          -> "ISO-8859-1",
    "utf_8"       -> "UTF-8",
    "utf8"        -> "UTF-8",
    "u8"          -> "UTF-8",
    "utf_8_sig"   -> "UTF-8",
    "mac_roman"   -> "x-MacRoman",
    "macroman"    -> "x-MacRoman",
    "ascii"       -> "US-ASCII",
    "646"         -> "US-ASCII"
  )

  def read(path: Path): String = decode(Files.readAllBytes(path))

  def decode(bytes: Array[Byte]): String =
    val hasBom  = bytes.startsWith(Utf8Bom)
    val body    = if hasBom then bytes.drop(Utf8Bom.length) else bytes
    val charset = if hasBom then StandardCharsets.UTF_8 else declaredCharset(body)
    val decoder = charset.newDecoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
    val text = decoder.decode(ByteBuffer.wrap(body)).toString
    joinLines(if text.startsWith("\uFEFF") then text.substring(1) else text)

  /** The charset named by the first or second line's coding cookie, UTF-8 when there is none. */
  def declaredCharset(bytes: Array[Byte]): Charset =
    val lines = firstLines(bytes, 2)
    val cookieLine =
        lines.headOption.filter(CodingCookie.matches)
            .orElse(lines.lift(1).filter(l =>
                CodingCookie.matches(l) && lines.headOption.exists(BlankOrComment.matches)
            ))
    cookieLine.collect { case CodingCookie(name) => name }.flatMap(charsetFor).getOrElse(
      StandardCharsets.UTF_8
    )

  /** The JVM charset for a Python codec name, normalised as `tokenize._get_normal_name` does. */
  def charsetFor(pythonName: String): Option[Charset] =
    val lower = pythonName.toLowerCase.replace('_', '-')
    val normal =
        if lower == "utf-8" || lower.startsWith("utf-8-") then "utf-8"
        else if Seq("latin-1", "iso-8859-1", "iso-latin-1").exists(n =>
              lower == n || lower.startsWith(n + "-")
          )
        then "iso-8859-1"
        else lower
    val candidates = Seq(
      normal,
      normal.replace('-', '_'),
      PythonCodecAliases.getOrElse(normal.replace('-', '_'), ""),
      if normal.matches("cp\\d+") then "windows-" + normal.drop(2) else ""
    ).filter(_.nonEmpty)
    candidates.iterator.flatMap(n => Try(Charset.forName(n)).toOption).nextOption()

  private def firstLines(bytes: Array[Byte], count: Int): Seq[String] =
    val latin1 = new String(bytes, 0, math.min(bytes.length, 4096), StandardCharsets.ISO_8859_1)
    latin1.split("\r\n|\r|\n", count + 1).take(count).toSeq

  private def joinLines(text: String): String =
    val normalised = text.replace("\r\n", "\n").replace('\r', '\n')
    if normalised.endsWith("\n") then normalised.dropRight(1) else normalised
end PythonSourceFile
