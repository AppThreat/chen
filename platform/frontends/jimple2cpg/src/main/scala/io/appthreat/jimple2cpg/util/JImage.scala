package io.appthreat.jimple2cpg.util

import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.{Files, Path, StandardOpenOption}
import java.nio.{ByteBuffer, ByteOrder}
import java.util.zip.Inflater
import scala.collection.mutable
import scala.util.{Try, Using}

/** A read-only reader for the jimage container (`lib/modules`) of a JDK 9 or later.
  *
  * Soot reads JDK classes through the `jrt:/` file system, which a GraalVM native image does not
  * provide for an arbitrary JDK. This reader opens the image file directly, so the JDK classes of
  * any installed JDK can be served to Soot from inside a native image. It is a port of the read
  * path of `jdk.internal.jimage.BasicImageReader` and depends on no JDK-internal API, so it works
  * the same on the JVM, where it can be tested against `jrt:/`.
  *
  * The image format (major version 1, minor version 0) has not changed since JDK 9:
  *
  * {{{
  *   header     7 x int: magic, version, flags, resource count, table length,
  *                       locations size, strings size
  *   redirect   int[table length]   perfect-hash redirect table
  *   offsets    int[table length]   offset of each location in `locations`
  *   locations  byte[]              attribute streams (module, parent, base, extension, ...)
  *   strings    byte[]              NUL-terminated modified UTF-8 strings
  *   resources  byte[]              resource content, from the end of the index
  * }}}
  *
  * The index is in the byte order of the platform that built the image; resource content may be
  * compressed with the `zip` plugin. Resources compressed with any other plugin (such as
  * `compact-cp`) are reported as unreadable rather than returned corrupt.
  *
  * The buffer is only ever read with absolute gets, so one instance can be shared between threads.
  */
final class JImage private (val path: Path, buffer: ByteBuffer, order: ByteOrder):

  import JImage.*

  private val tableLength   = buffer.getInt(16)
  private val locationsSize = buffer.getInt(20)
  private val stringsSize   = buffer.getInt(24)

  private val redirectOffset  = HeaderSize
  private val offsetsOffset   = redirectOffset + tableLength * 4
  private val locationsOffset = offsetsOffset + tableLength * 4
  private val stringsOffset   = locationsOffset + locationsSize

  /** The size of the index: resource content offsets are relative to this. */
  private val indexSize: Long = stringsOffset.toLong + stringsSize

  if indexSize > buffer.capacity() then
    throw new IOException(s"The image file '$path' is truncated")

  /** Package path (`java/lang`) to the modules that hold classes in it, built on first use. */
  private lazy val packageModules: Map[String, Vector[String]] =
    val index = mutable.LinkedHashMap.empty[String, Vector[String]]
    for i <- 0 until tableLength do
      val offset = redirectInt(offsetsOffset, i)
      if offset != 0 then
        val loc = location(offset)
        if loc.isClassFile then
          val modules = index.getOrElse(loc.parent, Vector.empty)
          if !modules.contains(loc.module) then index.update(loc.parent, modules :+ loc.module)
    index.toMap

  /** The names of the modules in this image. */
  lazy val moduleNames: Set[String] = packageModules.valuesIterator.flatten.toSet

  /** The number of class files in this image. */
  lazy val classCount: Int = entries.count(_.endsWith(".class"))

  /** The number of resources stored compressed. */
  private[util] def compressedEntries: Int =
      (0 until tableLength).iterator
          .map(i => redirectInt(offsetsOffset, i))
          .filter(_ != 0)
          .count(location(_).compressedSize != 0)

  /** All resource names, in the form `/module/parent/base.extension`. */
  def entries: Iterator[String] =
      (0 until tableLength).iterator
          .map(i => redirectInt(offsetsOffset, i))
          .filter(_ != 0)
          .map(location(_).fullName)

  /** Whether the image holds the class with the given internal name (`java/lang/Object`). */
  def containsClass(internalName: String): Boolean = findClassLocation(internalName).nonEmpty

  /** Read the class file with the given internal name (`java/lang/Object`), from whichever module
    * holds it. Returns None when the image has no such class or its content cannot be decoded.
    */
  def readClass(internalName: String): Option[Array[Byte]] =
      findClassLocation(internalName).flatMap(loc => Try(content(loc)).toOption)

  /** Read a resource by its full name (`/java.base/java/lang/Object.class`). */
  def read(fullName: String): Option[Array[Byte]] =
      findLocation(fullName).map(content)

  private def findClassLocation(internalName: String): Option[Location] =
    val slash  = internalName.lastIndexOf('/')
    val parent = if slash < 0 then "" else internalName.substring(0, slash)
    packageModules
        .getOrElse(parent, Vector.empty)
        .iterator
        .flatMap(module => findLocation(s"/$module/$internalName.class"))
        .nextOption()

  private def findLocation(fullName: String): Option[Location] =
    if tableLength == 0 then return None
    val slot  = nameHash(fullName, HashMultiplier) % tableLength
    val value = redirectInt(redirectOffset, slot)
    val index =
        if value < 0 then -value - 1
        else if value > 0 then nameHash(fullName, value) % tableLength
        else -1
    if index < 0 || index >= tableLength then None
    else
      val offset = redirectInt(offsetsOffset, index)
      // The perfect hash maps every name to some slot: confirm the slot holds this name.
      Option(location(offset)).filter(_.fullName == fullName)

  private def redirectInt(tableOffset: Int, index: Int): Int =
      buffer.getInt(tableOffset + index * 4)

  private def location(offset: Int): Location =
    if offset < 0 || offset >= locationsSize then
      throw new IOException(s"Bad jimage location offset $offset in '$path'")
    val attributes = new Array[Long](AttributeCount)
    var position   = locationsOffset + offset
    val limit      = locationsOffset + locationsSize
    var done       = false
    while !done && position < limit do
      val data = buffer.get(position) & 0xff
      position += 1
      if data <= 0x7 then done = true // ATTRIBUTE_END
      else
        val kind = data >>> 3
        if kind >= AttributeCount then
          throw new IOException(s"Invalid jimage attribute kind $kind in '$path'")
        val length = (data & 0x7) + 1
        var value  = 0L
        for i <- 0 until length do value = (value << 8) | (buffer.get(position + i) & 0xff)
        attributes(kind) = value
        position += length
    Location(
      module = string(attributes(AttributeModule).toInt),
      parent = string(attributes(AttributeParent).toInt),
      base = string(attributes(AttributeBase).toInt),
      extension = string(attributes(AttributeExtension).toInt),
      contentOffset = attributes(AttributeOffset),
      compressedSize = attributes(AttributeCompressed),
      uncompressedSize = attributes(AttributeUncompressed)
    )
  end location

  /** The NUL-terminated modified UTF-8 string at `offset` in the strings table. */
  private def string(offset: Int): String =
    if offset < 0 || offset >= stringsSize then
      throw new IOException(s"Bad jimage string offset $offset in '$path'")
    val start = stringsOffset + offset
    var end   = start
    val limit = stringsOffset + stringsSize
    while end < limit && buffer.get(end) != 0 do end += 1
    val bytes = new Array[Byte](end - start)
    buffer.get(start, bytes)
    decodeModifiedUtf8(bytes)

  private def content(loc: Location): Array[Byte] =
    if loc.uncompressedSize < 0 || loc.uncompressedSize > Int.MaxValue then
      throw new IOException(s"Bad uncompressed size for '${loc.fullName}'")
    if loc.compressedSize < 0 || loc.compressedSize > Int.MaxValue then
      throw new IOException(s"Bad compressed size for '${loc.fullName}'")
    val start = indexSize + loc.contentOffset
    val size  = if loc.compressedSize == 0 then loc.uncompressedSize else loc.compressedSize
    if start < 0 || start + size > buffer.capacity() then
      throw new IOException(s"Resource '${loc.fullName}' lies outside '$path'")
    val bytes = new Array[Byte](size.toInt)
    buffer.get(start.toInt, bytes)
    if loc.compressedSize == 0 then bytes else decompress(loc.fullName, bytes)

  /** Undo the compression plugins applied to a resource, outermost first. */
  private def decompress(name: String, compressed: Array[Byte]): Array[Byte] =
    var bytes = compressed
    var more  = true
    while more do
      compressedHeader(bytes) match
        case None => more = false
        case Some((uncompressed, pluginOffset)) =>
            string(pluginOffset) match
              case "zip" => bytes = inflate(name, bytes, CompressedHeaderSize, uncompressed)
              case other =>
                  throw new IOException(
                    s"Resource '$name' in '$path' uses the unsupported '$other' compression"
                  )
    bytes

  /** The uncompressed size and plugin-name offset of a compressed resource header, if present. */
  private def compressedHeader(bytes: Array[Byte]): Option[(Long, Int)] =
      if bytes.length < CompressedHeaderSize then None
      else
        val header = ByteBuffer.wrap(bytes, 0, CompressedHeaderSize).order(order)
        if header.getInt(0) != CompressedMagic then None
        else Some((header.getLong(12), header.getInt(20)))
end JImage

object JImage:

  private val Magic                = 0xcafedada
  private val CompressedMagic      = 0xcafefafa
  private val MajorVersion         = 1
  private val MinorVersion         = 0
  private val HeaderSize           = 7 * 4
  private val CompressedHeaderSize = 29
  private val HashMultiplier       = 0x01000193
  private val PositiveMask         = 0x7fffffff

  private val AttributeModule       = 1
  private val AttributeParent       = 2
  private val AttributeBase         = 3
  private val AttributeExtension    = 4
  private val AttributeOffset       = 5
  private val AttributeCompressed   = 6
  private val AttributeUncompressed = 7
  private val AttributeCount        = 8

  private final case class Location(
    module: String,
    parent: String,
    base: String,
    extension: String,
    contentOffset: Long,
    compressedSize: Long,
    uncompressedSize: Long
  ):
    /** The name as BasicImageReader builds it: `/module/parent/base.extension`. */
    def fullName: String =
      val builder = new StringBuilder
      if module.nonEmpty then builder.append('/').append(module).append('/')
      if parent.nonEmpty then builder.append(parent).append('/')
      builder.append(base)
      if extension.nonEmpty then builder.append('.').append(extension)
      builder.toString

    /** A class of a real module: not a `/packages` or `/modules` directory entry. */
    def isClassFile: Boolean =
        extension == "class" && module.nonEmpty && module != "packages" && module != "modules"
  end Location

  /** The image file of a JDK home, whether or not it exists. */
  def imageFile(javaHome: Path): Path = javaHome.resolve("lib").resolve("modules")

  /** Open a jimage file. Fails when the file is missing, is not a jimage or has an unknown version.
    */
  def open(path: Path): Try[JImage] = Try {
      if !Files.isRegularFile(path) then throw new IOException(s"'$path' is not a file")
      val mapped = Using.resource(FileChannel.open(path, StandardOpenOption.READ)) { channel =>
        if channel.size() < HeaderSize then
          throw new IOException(s"'$path' is not an image file")
        if channel.size() > Int.MaxValue then
          throw new IOException(s"'$path' is too large to map")
        // The mapping stays valid after the channel is closed.
        channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size())
      }
      val order = byteOrderOf(mapped).getOrElse(
        throw new IOException(s"'$path' is not an image file")
      )
      val buffer  = mapped.order(order)
      val version = buffer.getInt(4)
      val major   = version >>> 16
      val minor   = version & 0xffff
      if major != MajorVersion || minor != MinorVersion then
        throw new IOException(
          s"The image file '$path' has the unsupported version $major.$minor"
        )
      new JImage(path, buffer, order)
  }

  /** The byte order whose reading of the first int is the jimage magic. */
  private def byteOrderOf(buffer: ByteBuffer): Option[ByteOrder] =
      Seq(ByteOrder.nativeOrder(), ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)
          .find(o => buffer.duplicate().order(o).getInt(0) == Magic)

  /** The jimage perfect-hash function (`ImageStringsReader.hashCode`): FNV-1a style over the
    * modified UTF-8 bytes of the string.
    */
  private[util] def nameHash(s: String, seed: Int): Int =
    var hash = seed
    var i    = 0
    while i < s.length do
      val ch = s.charAt(i).toInt
      if ch == 0 then
        hash = (hash * HashMultiplier) ^ 0xc0
        hash = (hash * HashMultiplier) ^ 0x80
      else if (ch & ~0x7f) == 0 then hash = (hash * HashMultiplier) ^ ch
      else
        // Encode as modified UTF-8 (2 or 3 bytes; surrogates are encoded separately), then hash
        // the bytes from the lead byte on, as the JDK does.
        val encoded =
            if ch < 0x800 then Array(0xc0 | (ch >> 6), 0x80 | (ch & 0x3f))
            else Array(0xe0 | (ch >> 12), 0x80 | ((ch >> 6) & 0x3f), 0x80 | (ch & 0x3f))
        encoded.foreach(b => hash = (hash * HashMultiplier) ^ (b & 0xff))
      i += 1
    hash & PositiveMask

  /** Decode a modified UTF-8 byte sequence (no NUL terminator). */
  private[util] def decodeModifiedUtf8(bytes: Array[Byte]): String =
    val builder = new java.lang.StringBuilder(bytes.length)
    var i       = 0
    while i < bytes.length do
      val b = bytes(i) & 0xff
      if b < 0x80 then
        builder.append(b.toChar)
        i += 1
      else if (b & 0xe0) == 0xc0 && i + 1 < bytes.length then
        builder.append((((b & 0x1f) << 6) | (bytes(i + 1) & 0x3f)).toChar)
        i += 2
      else if (b & 0xf0) == 0xe0 && i + 2 < bytes.length then
        builder.append(
          (((b & 0x0f) << 12) | ((bytes(i + 1) & 0x3f) << 6) | (bytes(i + 2) & 0x3f)).toChar
        )
        i += 3
      else throw new IOException(s"Bad modified UTF-8 byte 0x${b.toHexString} in a jimage string")
    builder.toString

  private def inflate(name: String, bytes: Array[Byte], offset: Int, size: Long): Array[Byte] =
    if size < 0 || size > Int.MaxValue then
      throw new IOException(s"Bad uncompressed size $size for '$name'")
    val out      = new Array[Byte](size.toInt)
    val inflater = new Inflater()
    try
      inflater.setInput(bytes, offset, bytes.length - offset)
      var count = 0
      while !inflater.finished() && count < out.length do
        val n = inflater.inflate(out, count, out.length - count)
        if n == 0 && (inflater.needsInput() || inflater.needsDictionary()) then
          throw new IOException(s"Truncated compressed content for '$name'")
        count += n
      if count != out.length then throw new IOException(s"Size mismatch decompressing '$name'")
      out
    finally inflater.end()
end JImage
