package io.appthreat.pysrc2cpg

import org.slf4j.LoggerFactory

import java.io.{BufferedInputStream, InputStream}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, StandardCopyOption}
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.ZipFile
import scala.jdk.CollectionConverters.*
import scala.util.{Try, Using}

/** Task 12 Part A - ingestion of published Python package archives.
  *
  * A `.whl`/`.egg`/sdist dropped into the input directory (or given as the input itself) is
  * unpacked into a temp directory before [[io.appthreat.x2cpg.SourceFiles]] runs, so the file walk
  * sees the package's real layout and every existing rule (module naming, `src/` and `build/`
  * shadow handling, dependency attribution) applies to unpacked code unchanged.
  *
  * Formats, per the PyPA packaging specs and the real archives in the corpus:
  *   - `.whl` (PEP 427): zip container, `<pkg>/` + `<pkg>-<ver>.dist-info/` at the zip root
  *   - `.egg`: legacy zip container, `EGG-INFO/` at the root
  *   - sdist `.tar.gz` / `.tgz` and sdist `.zip`: a single `<pkg>-<ver>/` root, `PKG-INFO`, often a
  *     `src/` layout inside
  *   - `.pyz` / `.pyzw` (PEP 441 zipapp): `__main__.py` at the root - application code
  *   - `.pex`: zip container with vendored deps under `.bootstrap/` - application code
  *
  * NOT supported, deliberately (no bzip2/zstd/xz codec is on the classpath and the JDK ships none):
  * conda `.conda` (zstd payload), `.tar.bz2`, `.tar.xz`, 7z, rar. One given AS the input path is
  * refused loudly naming the archive - a documented gap, never a silent skip. One merely FOUND in
  * the input tree is left alone: an unrelated `docs/samples.7z` or a `.tar.xz` test fixture is not
  * a request to analyse it, and failing the whole run over an incidental file would deny analysis
  * of perfectly ordinary projects.
  *
  * SCOPE: archives are discovered at the TOP LEVEL of the input directory (or as the input path
  * itself), plus recursively inside archives already unpacked. A wheel buried at
  * `vendor/wheels/x.whl` is deliberately not unpacked - walking an arbitrary source tree for
  * archives would change what every existing project analysis ingests, so the wider scan is a
  * separate decision, not a side effect of this one.
  *
  * Security posture - this unpacks UNTRUSTED third-party archives inside a security tool, so every
  * extraction path is adversarial by default:
  *   - traversal entries (`..` segments) and absolute entry paths are refused;
  *   - the final destination is re-verified to sit under the extraction root after normalisation
  *     (defence in depth - the guard is not only the name check);
  *   - tar link entries are materialised only when they resolve inside the extraction root, and zip
  *     entries are ALWAYS written as regular files (a zip-encoded symlink's stored "target" becomes
  *     inert file content);
  *   - decompression bombs are bounded by a total-uncompressed-bytes and an entry-count ceiling
  *     shared across the WHOLE extraction (nested archives draw from one budget), with a clear
  *     error when exceeded. The byte ceiling is charged AS BYTES ARE WRITTEN, not per completed
  *     entry: a declared size is attacker-controlled, so the only enforceable bound is on what has
  *     actually reached the disk, and a single unbounded entry is precisely the case the ceiling
  *     exists for;
  *   - a tar metadata payload (a GNU long name, a pax header) is bounded before it is allocated -
  *     it is the one place a header's size field becomes an array length;
  *   - nested archives are unpacked recursively up to a depth of 10 (the jimple2cpg
  *     `unfoldArchives` bound), each into its own directory, never into the user's input tree.
  */
object PythonArchiveHandler:

  private val logger = LoggerFactory.getLogger(getClass)

  /** Zip-container extensions (the JDK's `java.util.zip` reads all of these). */
  val ZipExtensions: Set[String] = Set(".whl", ".egg", ".pyz", ".pyzw", ".pex", ".zip")

  /** tar+gzip extensions (sdist). */
  val TarGzExtensions: Set[String] = Set(".tar.gz", ".tgz")

  /** Total uncompressed bytes the whole extraction may write before it is treated as a bomb.
    * Generous against the largest real wheels (unpacked ML wheels reach a few GB); fatal for a zip
    * bomb orders of magnitude past that.
    */
  val MaxTotalUncompressedBytes: Long = 8L * 1024 * 1024 * 1024

  /** Entries across the whole extraction. A big wheel carries ~10k entries; six figures is already
    * pathological for a Python package.
    */
  val MaxEntries: Long = 200000L

  /** Recursion limit for archives inside archives (vendored wheels inside sdists etc.). */
  val MaxDepth: Int = 10

  /** Extensions recognised but NOT extractable with the codecs on the classpath. */
  val UnsupportedExtensions: Set[String] =
      Set(".conda", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".7z", ".rar")

  /** The largest a GNU long-name ('L') or pax ('x') metadata payload may be. These are read WHOLE
    * into a byte array to become a file name, so their size field - which is attacker-controlled -
    * has to be bounded before the allocation, not after: an `L` entry declaring 2 GiB would
    * otherwise allocate 2 GiB of heap (or throw `NegativeArraySizeException` past `Int.MaxValue`)
    * before any ceiling below could react. No real path approaches 64 KiB.
    */
  private val MaxMetadataEntryBytes: Long = 64L * 1024

  private case class Budget(var bytes: Long, var entries: Long, maxBytes: Long, maxEntries: Long):

    /** Charge bytes as they are written, not after the entry completes. Charging afterwards makes
      * the ceiling unenforceable in the one case it exists for: a SINGLE entry declaring - or, in a
      * zip, streaming - petabytes would be written to disk in full before its charge was ever
      * tested. The guard has to be able to stop mid-entry.
      */
    def charge(bytesDelta: Long): Unit =
      bytes += bytesDelta
      if bytes > maxBytes then
        throw RuntimeException(
          s"Archive extraction exceeded the ${maxBytes / (1024 * 1024)} MiB " +
              s"total-uncompressed-bytes ceiling ($bytes bytes written so far); refusing to " +
              "continue (decompression bomb?)"
        )

    def chargeEntry(): Unit =
      entries += 1
      if entries > maxEntries then
        throw RuntimeException(
          s"Archive extraction exceeded the $maxEntries entry ceiling; refusing to continue"
        )
  end Budget

  /** One unpacked archive: `root` is the directory whose children are the import roots (for a wheel
    * this is the zip root itself; for an sdist the single `<pkg>-<ver>/` directory inside it),
    * `archiveFile` the original archive for diagnostics.
    */
  case class ExtractedArchive(archiveFile: Path, root: Path)

  def isArchive(path: Path): Boolean =
      Files.isRegularFile(path) && archiveKindOf(path).isDefined

  /** Refuse an input we recognise but cannot open. Called ONLY for the input path itself: asking to
    * analyse `foo.conda` must fail loudly rather than analyse nothing, but an unrelated
    * `samples.7z` sitting in a source tree is not such a request, and a predicate used in a
    * `filter` must never throw - that turned every project carrying an incidental `.tar.xz` or
    * `.rar` fixture into a hard analysis failure.
    */
  private def refuseUnsupportedInput(path: Path): Unit =
    val n = path.getFileName.toString.toLowerCase
    if Files.isRegularFile(path) && UnsupportedExtensions.exists(n.endsWith) then
      throw RuntimeException(
        s"Unsupported archive format '$n' (needs a bzip2/zstd/xz codec the classpath does not " +
            s"carry): $path"
      )

  /** Is this archive a Python *application* container (code under analysis) rather than an
    * installable distribution? zipapps (PEP 441) and PEX files are programs; wheels, eggs and
    * sdists are dependencies when found inside a project.
    */
  def isApplicationArchive(path: Path): Boolean =
    val n = path.getFileName.toString.toLowerCase
    n.endsWith(".pyz") || n.endsWith(".pyzw") || n.endsWith(".pex")

  private def archiveKindOf(path: Path): Option[String] =
    val n = path.getFileName.toString.toLowerCase
    if ZipExtensions.exists(n.endsWith) then Some(n)
    else if TarGzExtensions.exists(n.endsWith) then Some(n)
    else None

  /** Extract the archives at the top level of the `input` directory - or `input` itself when it is
    * an archive file - into `tempRoot`, then any archive found inside what was just unpacked, to
    * the depth bound. Returns one [[ExtractedArchive]] per unpacked archive, in deterministic
    * (path-sorted) order. Throws on bomb ceilings, traversal entries and an unsupported input
    * format - never a partial extraction without a diagnostic.
    *
    * "Top level", not a recursive walk of the input tree: see the SCOPE note on the object. The
    * recursion applies to archives nested INSIDE archives, which is a property of the distribution
    * being ingested rather than of the user's directory layout.
    */
  def extractArchives(input: Path, tempRoot: Path): Seq[ExtractedArchive] =
      extractArchivesWithLimits(input, tempRoot, MaxTotalUncompressedBytes, MaxEntries, MaxDepth)

  /** The same extraction with injectable ceilings, so the bomb guards are testable without
    * manufacturing multi-gigabyte fixtures.
    */
  private[pysrc2cpg] def extractArchivesWithLimits(
    input: Path,
    tempRoot: Path,
    maxTotalUncompressedBytes: Long,
    maxEntries: Long,
    maxDepth: Int
  ): Seq[ExtractedArchive] =
    refuseUnsupportedInput(input)
    val budget = Budget(0, 0, maxTotalUncompressedBytes, maxEntries)
    val out    = Seq.newBuilder[ExtractedArchive]
    val archives =
        if isArchive(input) then Seq(input)
        else if Files.isDirectory(input) then listDirSorted(input).filter(isArchive)
        else Seq.empty
    unpackAll(archives, tempRoot, depth = 0, budget, maxDepth, out, AtomicInteger(0))
    out.result()

  private def unpackAll(
    archives: Seq[Path],
    tempRoot: Path,
    depth: Int,
    budget: Budget,
    maxDepth: Int,
    out: collection.mutable.Builder[ExtractedArchive, Seq[ExtractedArchive]],
    counter: AtomicInteger
  ): Unit =
    if depth > maxDepth then
      logger.warn(
        s"Archive nesting deeper than $maxDepth levels is not unpacked (recursion stopped)"
      )
      return
    archives.foreach { archive =>
        archiveKindOf(archive) match
          case None       => () // unreachable through isArchive, kept for total match
          case Some(kind) =>
              // The sequence number, not just the file name: two archives with the SAME file
              // name (`a/pkg.whl` and `b/pkg.whl`, or a sanitised-name clash) would otherwise
              // resolve to one directory and extract INTO EACH OTHER - silently merging two
              // distribution trees, and yielding two ExtractedArchive entries pointing at one
              // root with whichever identity metadata survived. The counter keeps the name
              // deterministic (extraction order is sorted) and unique.
              val dest = tempRoot.resolve(
                s"a${counter.getAndIncrement()}-d$depth-${sanitisedName(archive)}"
              )
              if TarGzExtensions.exists(kind.endsWith) then untarGzTo(archive, dest, budget)
              else unzipTo(archive, dest, budget)
              val root = packageRootOf(dest)
              out += ExtractedArchive(archive, root)
              // Nested archives (a vendored wheel inside an sdist): unpack in turn.
              val nested = walkSorted(root).filter(isArchive)
              if nested.nonEmpty then
                unpackAll(nested, tempRoot, depth + 1, budget, maxDepth, out, counter)
    }
  end unpackAll

  /** The directory whose children are the import roots. A wheel/egg/zipapp/pex root is the
    * extraction dir itself; an sdist packs everything under a single `<pkg>-<ver>/` directory,
    * which is unwrapped so the package layout starts at the right level and the `src/` and `build/`
    * shadow handling in [[Py2CpgOnFileSystem]] sees the layout the sdist author intended.
    */
  private def packageRootOf(dest: Path): Path =
    val entries  = listDirSorted(dest)
    val topDirs  = entries.filter(Files.isDirectory(_))
    val topFiles = entries.filterNot(Files.isDirectory(_))
    if topFiles.isEmpty && topDirs.length == 1 then topDirs.head else dest

  private def listDirSorted(dir: Path): Seq[Path] =
      if !Files.isDirectory(dir) then Nil
      else
        Try(Using.resource(Files.list(dir))(_.iterator().asScala.toSeq)).getOrElse(Nil)
            .sortBy(_.getFileName.toString)

  /** Every regular file under `root`, path-sorted. The walk stream is CLOSED - `Files.walk` holds
    * an open directory handle per level, and leaking one per archive per call (this runs for
    * nested-archive discovery and again for the layout fallback) exhausts descriptors on a large
    * unpacked tree.
    */
  private def walkSorted(root: Path): Seq[Path] =
      if !Files.isDirectory(root) then Nil
      else
        Try(Using.resource(Files.walk(root))(_.iterator().asScala.toSeq)).getOrElse(Nil)
            .filter(Files.isRegularFile(_))
            .sortBy(_.toString)

  private def sanitisedName(archive: Path): String =
      archive.getFileName.toString.replaceAll("[^A-Za-z0-9._-]", "_")

  // ------------------------------------------------------------------ package identity (A.4)

  /** The authoritative distribution identity of an unpacked archive: distribution name, version,
    * and the top-level import names it provides. This is what a `.whl`'s RECORD (or an older
    * wheel's / egg's `top_level.txt`, or an sdist's `PKG-INFO` plus its layout) states outright -
    * as opposed to the `internal:Namespaces` guesswork an SBOM path has to fall back on when the
    * package was never unpacked (SBOM doc Finding 3).
    */
  case class PackageIdentity(name: String, version: String, importNames: List[String]):

    /** The purl spec requires a pypi name in its PEP 503 normalised form - lowercased with runs of
      * `-`, `_` and `.` collapsed to a single `-`. Lowercasing alone leaves
      * `pkg:pypi/typing_extensions@…`, which compares unequal to the `pkg:pypi/typing-extensions@…`
      * every SBOM and advisory feed carries, so an unpacked distribution would be attributed under
      * a purl that matches nothing - the failure being invisible, since a tag was still written.
      */
    def purl: String = s"pkg:pypi/${PackageIdentity.normalise(name)}@$version"

  object PackageIdentity:
    def normalise(name: String): String =
        name.trim.toLowerCase.replaceAll("[-_.]+", "-")

  /** Read the package identity off an extraction root. `None` when the root carries no packaging
    * metadata (a zipapp, a PEX, a bare vendored tree) - those are ingested without a purl, which is
    * the honest answer.
    */
  def packageIdentity(root: Path): Option[PackageIdentity] =
      distInfoIdentity(root).orElse(eggInfoIdentity(root).orElse(sdistIdentity(root)))

  private def distInfoIdentity(root: Path): Option[PackageIdentity] =
    val distInfo = listDirSorted(root).find(_.getFileName.toString.endsWith(".dist-info"))
    distInfo.flatMap { di =>
      val (name, version) = nameVersionOfMetadata(di.resolve("METADATA"))
          .getOrElse {
              // The dist-info directory name itself is `<distribution>-<version>`.
              val parts = di.getFileName.toString.stripSuffix(".dist-info").split("-")
              (parts.dropRight(1).mkString("-"), parts.takeRight(1).mkString(""))
          }
      val importNames = topLevelTxtOf(di).orElse(recordTopsOf(di)) match
        case Some(names) => names
        case None        => layoutTopsOf(root)
      if name.isEmpty then None else Some(PackageIdentity(name, version, importNames))
    }

  private def eggInfoIdentity(root: Path): Option[PackageIdentity] =
    val eggInfo = listDirSorted(root).find(_.getFileName.toString == "EGG-INFO")
    eggInfo.flatMap { ei =>
        nameVersionOfMetadata(ei.resolve("PKG-INFO")).map { (name, version) =>
            PackageIdentity(name, version, topLevelTxtOf(ei).getOrElse(layoutTopsOf(root)))
        }
    }

  private def sdistIdentity(root: Path): Option[PackageIdentity] =
      // After root unwrapping, an sdist's PKG-INFO sits directly under the root.
      nameVersionOfMetadata(root.resolve("PKG-INFO")).map { (name, version) =>
          PackageIdentity(name, version, layoutTopsOf(root))
      }

  /** `Name:`/`Version:` headers from a core-metadata file (METADATA / PKG-INFO). */
  private def nameVersionOfMetadata(file: Path): Option[(String, String)] =
      if !Files.isRegularFile(file) then None
      else
        val lines = Try(
          Using.resource(Files.newBufferedReader(file, StandardCharsets.UTF_8)) { r =>
              Iterator.continually(r.readLine()).takeWhile(_ != null).takeWhile(!_.isEmpty).toSeq
          }
        ).getOrElse(Seq.empty)
        val header = lines.map(_.split(":", 2)).collect {
            case Array(k, v) => k.trim.toLowerCase -> v.trim
        }.toMap
        for name <- header.get("name"); version <- header.get("version") yield (name, version)

  /** `top_level.txt`: one import name per line (older wheels, eggs). */
  private def topLevelTxtOf(infoDir: Path): Option[List[String]] =
    val f = infoDir.resolve("top_level.txt")
    if !Files.isRegularFile(f) then None
    else
      Some(
        Try(
          Using.resource(Files.newBufferedReader(f, StandardCharsets.UTF_8)) { r =>
              Iterator.continually(r.readLine()).takeWhile(_ != null).map(_.trim)
                  .filter(_.nonEmpty).toList
          }
        ).getOrElse(Nil)
      )

  /** A wheel's RECORD is the authoritative file list: every installed path, one per line, as
    * `path,hash,size`. The top-level import names are the distinct leading path segments of the
    * `.py` entries, excluding packaging metadata directories - a mapping stated by the wheel itself
    * rather than inferred.
    */
  private def recordTopsOf(distInfo: Path): Option[List[String]] =
    val record = distInfo.resolve("RECORD")
    if !Files.isRegularFile(record) then None
    else
      val lines = Try(
        Using.resource(Files.newBufferedReader(record, StandardCharsets.UTF_8)) { r =>
            Iterator.continually(r.readLine()).takeWhile(_ != null).toList
        }
      ).getOrElse(Nil)
      val tops = lines.flatMap { line =>
        val path       = line.split(",", 2).headOption.getOrElse("")
        val normalized = path.replace('\\', '/')
        val segments   = normalized.split('/')
        segments.headOption.filter { top =>
            normalized.endsWith(".py") &&
            !top.endsWith(".dist-info") && !top.endsWith(".data") &&
            !top.endsWith(".egg-info")
        }
            // A single-module distribution ships `six.py` / `typing_extensions.py` at the ROOT,
            // so the leading segment IS the file name. The import name is `six`, not `six.py`,
            // and leaving the suffix on silently lost purl attribution for every single-module
            // wheel - the tag was simply never applied, because no module ever matches.
            .map(_.stripSuffix(".py"))
      }.distinct
      Option.when(tops.nonEmpty)(tops)
    end if
  end recordTopsOf

  /** Layout fallback: the distinct top-level import names of every `.py` file under the root
    * (`src/mypkg/mod.py` -> `mypkg`; a root-level `requests.py` -> `requests`). Last resort only -
    * RECORD and top_level.txt are the authorities.
    *
    * The `src/` hop is stripped, exactly as [[PythonModuleName]] strips it when it computes the
    * module names these are matched against. Without that, an sdist's src layout produced the
    * single import name `"src"` - which happens to tag the right files by accident, while also
    * tagging a root-level `setup.py` and reporting an import name no interpreter would recognise.
    */
  private def layoutTopsOf(root: Path): List[String] =
      walkSorted(root)
          .map(root.relativize(_).toString.replace('\\', '/'))
          .filter(_.endsWith(".py"))
          .map(importTopOf)
          .filterNot(top => top.isEmpty || top.endsWith(".dist-info") || top.endsWith(".egg-info"))
          .distinct
          .toList

  /** The top-level import name a root-relative `.py` path contributes, `src/` hop removed. Shared
    * with the ingestion side so identity and matching cannot drift apart.
    */
  private[pysrc2cpg] def importTopOf(rel: String): String =
    val segments = rel.split('/').toSeq
    val useful   = if segments.headOption.contains("src") then segments.drop(1) else segments
    useful.headOption.getOrElse("").stripSuffix(".py")

  // ------------------------------------------------------------------ zip

  /** Safe zip extraction. Unlike the shared `FileUtil.unzipTo`, every entry name is validated (no
    * traversal, no absolute path) and the written destination is re-verified against the extraction
    * root after normalisation. Zip-encoded symlinks (unix mode bits in the external attributes) are
    * written as regular files: their stored "target" becomes inert content.
    */
  private def unzipTo(archive: Path, dest: Path, budget: Budget): Unit =
      Using.resource(new ZipFile(archive.toFile)) { zipFile =>
        Files.createDirectories(dest)
        zipFile.entries().asScala.toSeq.sortBy(_.getName).foreach { entry =>
          budget.chargeEntry()
          if entry.isDirectory then Files.createDirectories(safeDestination(dest, entry.getName))
          else
            val child = safeDestination(dest, entry.getName)
            Files.createDirectories(child.getParent)
            // Scoped PER ENTRY. A `Using.Manager` registration inside this loop releases
            // nothing until the whole archive is done, so a wheel with ten thousand entries
            // held ten thousand open descriptors at once and died on `EMFILE` long before any
            // ceiling applied. Small test fixtures hid it completely.
            Using.resource(zipFile.getInputStream(entry)) { in =>
                Using.resource(Files.newOutputStream(child))(out => pipe(in, out, budget))
            }
        }
      }

  // ------------------------------------------------------------------ tar + gzip

  /** Safe tar+gzip extraction (sdists). The tar container is read sequentially in 512-byte blocks;
    * GNU long names ('L'), pax extended headers ('x') and the ustar prefix field are honoured. Link
    * entries are materialised only when they resolve inside the extraction root; anything escaping
    * it is refused. Each entry is exactly one 512-byte header block followed by its data padded to
    * a block boundary.
    */
  private def untarGzTo(archive: Path, dest: Path, budget: Budget): Unit =
      Using.resource(
        new java.util.zip.GZIPInputStream(
          new BufferedInputStream(Files.newInputStream(archive), 1 << 16)
        )
      ) { gzipIn =>
        Files.createDirectories(dest)
        var pendingLongName: Option[String] = None
        var pendingPaxPath: Option[String]  = None
        var continue                        = true
        while continue do
          readBlock(gzipIn) match
            case None =>
                continue =
                    false // end of stream (possibly truncated - data reads below fail loudly)
            case Some(block) if block.forall(_ == 0) =>
                continue = false // end-of-archive marker
            case Some(block) =>
                TarHeader.parse(block) match
                  case scala.util.Left(err) =>
                      throw RuntimeException(s"Malformed tar header in $archive: $err")
                  case scala.util.Right(entry) =>
                      val isMeta = entry.typeFlag == TarHeader.TypeFlagLongName ||
                          entry.typeFlag == TarHeader.TypeFlagPaxExtended ||
                          entry.typeFlag == TarHeader.TypeFlagPaxGlobal
                      if isMeta then
                        val data = readDataString(gzipIn, entry.size, budget)
                        if entry.typeFlag == TarHeader.TypeFlagLongName then
                          pendingLongName = Some(data)
                        else if entry.typeFlag == TarHeader.TypeFlagPaxExtended then
                          pendingPaxPath = paxPathOf(data).orElse(pendingPaxPath)
                        // A global header carries archive-wide defaults; it names no entry, so
                        // it must not disturb a pending per-entry name.
                      else
                        val name = pendingPaxPath
                            .orElse(pendingLongName)
                            .getOrElse(entry.name)
                        pendingLongName = None
                        pendingPaxPath = None
                        budget.chargeEntry()
                        entry.typeFlag match
                          case TarHeader.TypeFlagDir =>
                              Files.createDirectories(
                                safeDestination(dest, stripTrailingSlash(name))
                              )
                          case TarHeader.TypeFlagSymlink =>
                              extractTarSymlink(dest, name, entry.linkName)
                          case TarHeader.TypeFlagHardLink =>
                              extractTarHardLink(dest, name, entry.linkName)
                          case TarHeader.TypeFlagRegular | '\u0000' =>
                              val child = safeDestination(dest, name)
                              Files.createDirectories(child.getParent)
                              Using.resource(Files.newOutputStream(child))(out =>
                                  pipeCounting(gzipIn, out, entry.size, budget)
                              )
                          case flag =>
                              // Character/block devices, fifos, sparse files: not Python
                              // source; skipped without materialising anything.
                              skipData(gzipIn, entry.size)
                              logger.debug(
                                s"Ignoring tar entry '$name' of type '$flag'"
                              )
                        end match
                      end if
                      skipPadding(gzipIn, entry.size)
        end while
      }
  end untarGzTo

  private def extractTarSymlink(dest: Path, name: String, linkName: String): Unit =
    val child  = safeDestination(dest, name)
    val target = child.getParent.resolve(linkName).normalize
    if !target.startsWith(dest) then
      throw RuntimeException(
        s"Refusing tar symlink '$name' -> '$linkName': target escapes the extraction directory"
      )
    Files.createDirectories(child.getParent)
    // Some archives emit the same symlink twice; POSIX link creation would fail on the second.
    Files.deleteIfExists(child)
    Files.createSymbolicLink(child, child.getParent.relativize(target))

  private def extractTarHardLink(dest: Path, name: String, linkName: String): Unit =
    val child  = safeDestination(dest, name)
    val target = dest.resolve(linkName).normalize
    if !target.startsWith(dest) then
      throw RuntimeException(
        s"Refusing tar hardlink '$name' -> '$linkName': target escapes the extraction directory"
      )
    if Files.isRegularFile(target) then
      Files.createDirectories(child.getParent)
      Files.copy(target, child, StandardCopyOption.REPLACE_EXISTING)
    else
      logger.debug(
        s"Tar hardlink '$name' -> '$linkName' referenced a missing or non-file entry; skipped"
      )

  /** The one name-shape gate every entry passes: no absolute paths, no `..` segments, no backslash
    * tricks - and the resolved destination is re-verified to sit under `dest` after normalisation,
    * so the check does not depend on the string test alone.
    */
  private def safeDestination(dest: Path, rawName: String): Path =
    val name = rawName.replace('\\', '/')
    if name.isEmpty || name.startsWith("/") || name.split('/').contains("..") then
      throw RuntimeException(s"Refusing archive entry '$rawName': traversal or absolute path")
    // Windows drive letters have no business in a portable Python archive.
    if name.length >= 2 && name.charAt(1) == ':' then
      throw RuntimeException(s"Refusing archive entry '$rawName': drive-absolute path")
    val child = dest.resolve(name).normalize
    if !child.startsWith(dest) then
      throw RuntimeException(
        s"Refusing archive entry '$rawName': resolves outside the extraction directory"
      )
    child

  private def stripTrailingSlash(name: String): String =
      if name.endsWith("/") then name.dropRight(1) else name

  private def readBlock(in: InputStream): Option[Array[Byte]] =
    val block = Array.ofDim[Byte](512)
    var off   = 0
    while off < 512 do
      val n = in.read(block, off, 512 - off)
      if n < 0 then
        return if off == 0 then None else Some(block.take(off))
      off += n
    Some(block)

  /** Read a metadata payload (a GNU long name or a pax header block) as a string. The size is
    * bounded BEFORE the allocation and charged to the budget: it comes straight out of an
    * attacker-controlled header field, and this is the one place a header size becomes an array
    * length. An `L` entry declaring 2 GiB would otherwise allocate 2 GiB (or overflow `Int` into a
    * `NegativeArraySizeException`) with no ceiling able to react.
    */
  private def readDataString(in: InputStream, size: Long, budget: Budget): String =
    if size < 0 || size > MaxMetadataEntryBytes then
      throw RuntimeException(
        s"Refusing tar metadata entry of $size bytes (ceiling $MaxMetadataEntryBytes): a name " +
            "or pax header this large is not a name"
      )
    budget.charge(size)
    val data = readExact(in, size)
    // GNU long names are NUL-terminated; some writers terminate with a newline instead.
    new String(data, StandardCharsets.UTF_8).takeWhile(c => c != '\u0000' && c != '\n').trim

  private def readExact(in: InputStream, size: Long): Array[Byte] =
    val data = Array.ofDim[Byte](size.toInt)
    var off  = 0
    while off < data.length do
      val n = in.read(data, off, data.length - off)
      if n < 0 then throw RuntimeException("Truncated archive: entry data ends early")
      off += n
    data

  /** Copy exactly `size` bytes, charging the budget as they are written. */
  private def pipeCounting(
    in: InputStream,
    out: java.io.OutputStream,
    size: Long,
    budget: Budget
  ): Unit =
    val buffer    = Array.ofDim[Byte](1 << 16)
    var remaining = size
    while remaining > 0 do
      val n = in.read(buffer, 0, math.min(buffer.length.toLong, remaining).toInt)
      if n < 0 then throw RuntimeException("Truncated archive: entry data ends early")
      out.write(buffer, 0, n)
      budget.charge(n)
      remaining -= n
    out.flush()

  /** Copy a stream of unknown length (zip entries), charging the budget as bytes are written. The
    * charge is incremental because the length is not knowable in advance: a zip's declared sizes
    * are attacker-controlled, so the only honest bound is on what has actually been written.
    */
  private def pipe(in: InputStream, out: java.io.OutputStream, budget: Budget): Unit =
    val buffer = Array.ofDim[Byte](1 << 16)
    var n      = in.read(buffer)
    while n >= 0 do
      if n > 0 then
        out.write(buffer, 0, n)
        budget.charge(n)
      n = in.read(buffer)
    out.flush()

  private def skipData(in: InputStream, size: Long): Unit =
    var remaining = size
    val buffer    = Array.ofDim[Byte](1 << 16)
    while remaining > 0 do
      val n = in.read(buffer, 0, math.min(buffer.length.toLong, remaining).toInt)
      if n < 0 then throw RuntimeException("Truncated archive: entry data ends early")
      remaining -= n

  private def skipPadding(in: InputStream, size: Long): Unit =
    val rem = (512 - (size % 512)) % 512
    if rem > 0 then skipData(in, rem)

  /** `path=` from a pax extended header, whose payload is `<len> <key>=<value>\n` records. */
  private def paxPathOf(pax: String): Option[String] =
      pax.split('\n').flatMap { record =>
        val space = record.indexOf(' ')
        if space > 0 then
          val kv = record.substring(space + 1)
          val eq = kv.indexOf('=')
          if eq > 0 && kv.substring(0, eq) == "path" then Some(kv.substring(eq + 1)) else None
        else None
      }.headOption

  // ------------------------------------------------------------------ tar headers

  private object TarHeader:
    val TypeFlagRegular     = '0'
    val TypeFlagHardLink    = '1'
    val TypeFlagSymlink     = '2'
    val TypeFlagDir         = '5'
    val TypeFlagLongName    = 'L'
    val TypeFlagPaxExtended = 'x'

    /** A pax GLOBAL header applies to the rest of the archive, not to the next entry. It is
      * metadata all the same: treating it as an ordinary entry made it CONSUME a pending `x` path
      * as if it were its own name, so a `pax_global_header` emitted between an entry's extended
      * header and the entry itself silently discarded that entry's real long path.
      */
    val TypeFlagPaxGlobal = 'g'

    case class Entry(name: String, linkName: String, size: Long, typeFlag: Char)

    def parse(block: Array[Byte]): Either[String, Entry] =
      if block.length < 512 then Left("short header block")
      else
        val name =
          val base   = cString(block, 0, 100)
          val magic  = cString(block, 257, 8)
          val prefix = cString(block, 345, 155)
          if prefix.nonEmpty && magic.startsWith("ustar") then s"$prefix/$base" else base
        // Verify the checksum: it is computed over the header with the checksum field
        // itself read as spaces. A mismatch means a corrupt or crafted archive.
        //
        // BOTH the unsigned and the signed sum are accepted. The unsigned form is what the
        // spec intends and what modern writers emit, but a historic family of tar
        // implementations summed the header bytes as SIGNED chars, and an archive written by
        // one is perfectly valid - rejecting it fails the entire analysis of a legitimate
        // sdist over a byte-signedness convention. Accepting either is what every real tar
        // reader does; it costs no security, since an attacker able to pick the bytes can
        // satisfy whichever form is checked.
        val stored = readOctal(block, 148, 8)
        val unsigned =
            (0 until 512).map(i => if i >= 148 && i < 156 then 32 else block(i).toInt & 0xff).sum
        val signed =
            (0 until 512).map(i => if i >= 148 && i < 156 then 32 else block(i).toInt).sum
        if stored != unsigned && stored != signed then
          Left(s"checksum mismatch (stored $stored, computed $unsigned)")
        else
          Right(Entry(
            name,
            cString(block, 157, 100),
            readOctal(block, 124, 12),
            block(
              156
            ).toChar
          ))
      end if
    end parse

    private def cString(block: Array[Byte], off: Int, len: Int): String =
      val end = (off until math.min(off + len, block.length)).find(i => block(i) == 0).getOrElse(
        math.min(off + len, block.length)
      )
      new String(block, off, end - off, StandardCharsets.UTF_8)

    /** Octal ASCII with the GNU base-256 extension (high bit of the first byte set). */
    private def readOctal(block: Array[Byte], off: Int, len: Int): Long =
        if (block(off).toInt & 0x80) != 0 then
          var value = 0L
          (off until off + len).foreach { i => value = (value << 8) | (block(i).toLong & 0xff) }
          value & 0x7fffffffffffffffL
        else
          val text = cString(block, off, len).trim
          if text.isEmpty then 0L
          else
            Try(java.lang.Long.parseLong(text, 8)).getOrElse(
              throw RuntimeException(s"Bad octal size field '$text'")
            )
  end TarHeader
end PythonArchiveHandler
