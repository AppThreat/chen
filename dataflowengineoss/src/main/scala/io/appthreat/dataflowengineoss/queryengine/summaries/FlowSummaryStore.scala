package io.appthreat.dataflowengineoss.queryengine.summaries

import io.appthreat.dataflowengineoss.semanticsloader.Semantics
import io.appthreat.x2cpg.passes.frontend.CacheControl
import io.appthreat.x2cpg.utils.AtomicWrites
import io.circe.parser.decode
import io.circe.syntax.EncoderOps
import io.circe.{Decoder, Encoder}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*
import org.slf4j.LoggerFactory

import java.nio.file.{Files, LinkOption, Path, Paths}
import java.security.MessageDigest
import scala.util.Try

/** On-disk persistence for the set of [[MethodFlowSummary]] facts computed for a graph.
  *
  * Summaries depend only on the method bodies and the call graph, so the cache is keyed on a
  * fingerprint of every internal method's signature and source. When the fingerprint matches a
  * previously stored set, the summaries are restored instead of recomputed; any change to a method
  * body changes the fingerprint and forces a recompute. The store is gated by
  * [[CacheControl.Summary]] and is off by default.
  */
object FlowSummaryStore:

  /** Bumped whenever the summary format or the way summaries are computed changes, so older cached
    * files are not read back with a newer reader.
    */
  private val FormatVersion = "flowsummary-v1"

  given Encoder[MethodFlowSummary] = Encoder.forProduct5(
    "methodFullName",
    "paramToReturn",
    "paramToParamOut",
    "returnFromInternal",
    "paramOutFromInternal"
  )(s =>
      (
        s.methodFullName,
        s.paramToReturn,
        s.paramToParamOut,
        s.returnFromInternal,
        s.paramOutFromInternal
      )
  )

  given Decoder[MethodFlowSummary] = Decoder.forProduct5(
    "methodFullName",
    "paramToReturn",
    "paramToParamOut",
    "returnFromInternal",
    "paramOutFromInternal"
  )(MethodFlowSummary.apply)

  /** A fingerprint over every internal method's full name, signature and source, plus the format
    * version. Two graphs with the same method bodies produce the same fingerprint, so a stored
    * summary set is reused across runs as long as no method body changed.
    */
  def fingerprint(cpg: Cpg, semantics: Semantics = Semantics.empty): String =
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(FormatVersion.getBytes("UTF-8"))
    digest.update(semantics.serialize.getBytes("UTF-8"))
    cpg.method.internal.l
        .map(m => s"${m.fullName}\u0000${m.signature}\u0000${m.code}")
        .sorted
        .foreach(entry => digest.update(entry.getBytes("UTF-8")))
    digest.digest().map("%02x".format(_)).mkString

  def serialize(summaries: Map[String, MethodFlowSummary]): String =
      summaries.values.toSeq.sortBy(_.methodFullName).asJson.noSpaces

  def deserialize(json: String): Either[String, Map[String, MethodFlowSummary]] =
      decode[Seq[MethodFlowSummary]](json) match
        case Right(list) => Right(list.map(s => s.methodFullName -> s).toMap)
        case Left(err)   => Left(err.getMessage)
end FlowSummaryStore

/** Reads and writes summary sets keyed on a fingerprint, under `cacheDir`.
  *
  * The directory is the one holding the user-named slices file, so it is trusted as a position the
  * user chose; the files inside it are still written so that a symbolic link at an entry's name
  * cannot redirect them, and read so that a linked entry is a miss rather than a read of wherever
  * the link points.
  */
class FlowSummaryStore(cacheDir: String):

  private val logger = LoggerFactory.getLogger(classOf[FlowSummaryStore])

  private val cacheDirParentExists: Boolean =
      Try {
          Files.isDirectory(Option(Paths.get(cacheDir).getParent).getOrElse(Paths.get(".")))
      }.getOrElse(false)

  private def enabled: Boolean =
      cacheDir.nonEmpty && cacheDirParentExists && CacheControl.isEnabled(CacheControl.Summary)

  if enabled then
    Try(Files.createDirectories(Paths.get(cacheDir))).failed.foreach { e =>
        logger.warn(s"Failed to create summary cache directory $cacheDir: ${e.getMessage}")
    }

  private def cacheFile(fingerprint: String): Path =
      Paths.get(cacheDir, s"flowsummary-$fingerprint.json")

  /** Restore the summary set stored under `fingerprint`, if present and readable. An entry that is
    * a symbolic link is a miss: its target is never read.
    */
  def restore(fingerprint: String): Option[Map[String, MethodFlowSummary]] =
      if !enabled then None
      else
        val cached = cacheFile(fingerprint)
        if !Files.isRegularFile(cached, LinkOption.NOFOLLOW_LINKS) then
          if Files.exists(cached, LinkOption.NOFOLLOW_LINKS) then
            logger.debug(s"Summary cache entry $cached is not a regular file; treating it as a miss")
          None
        else
          Try(Files.readString(cached)).toOption
              .flatMap(json => FlowSummaryStore.deserialize(json).toOption)

  /** Store `summaries` under `fingerprint`, replacing any existing entry atomically through an
    * unpredictable temporary in the same directory, so a link committed at either name is replaced
    * rather than written through.
    */
  def store(fingerprint: String, summaries: Map[String, MethodFlowSummary]): Unit =
      if enabled then
        Try(AtomicWrites.text(cacheFile(fingerprint), FlowSummaryStore.serialize(summaries)))
            .failed.foreach { e =>
              logger.warn(s"Failed to store summary cache: ${e.getMessage}")
            }
end FlowSummaryStore
