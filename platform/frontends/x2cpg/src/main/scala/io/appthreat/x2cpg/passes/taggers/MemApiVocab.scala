package io.appthreat.x2cpg.passes.taggers

import io.circe.parser.*

import scala.io.Source
import scala.util.Using

/** The memory-API vocabulary used by [[MemoryApiPass]], loaded from the versioned
  * `memory-apis.json` resource so that adding an API (or a project's in-house wrapper) is a data
  * change with no recompile - the same shape as [[CdxTagVocab]]'s vendored cdxgen vocabulary.
  *
  * An external config (JSON of the same schema, `{"apis": [...]}`) is merged OVER the built-in
  * inventory, entry name deciding: a team can redefine `memcpy`'s roles for their platform or
  * declare `av_memcpy` without patching chen, mirroring how `ChennaiTagsPass` consumes
  * `--validation-config`.
  */
object MemApiVocab:

  final val ResourcePath = "memory-apis.json"

  /** A memory API and the roles of its arguments. Indices are 1-based argument positions.
    *
    * @param dst
    *   argument the API writes its result into (the copy destination).
    * @param src
    *   argument the copied/read data comes from.
    * @param len
    *   argument that bounds the operation (byte count, capacity).
    * @param alloc
    *   allocation family of the call (`heap`, `new`, `new[]`, `mmap`, `file`, `socket`).
    * @param free
    *   release family of the call; `realloc` carries both, it releases its first argument.
    * @param untrustedRead
    *   argument the API fills with untrusted data (the buffer a `read`/`recv`/`fgets` fills).
    * @param untrustedCall
    *   true when the call's result or variadic outputs are untrusted but no single buffer argument
    *   exists (`getenv`, the scanf family).
    */
  final case class MemApiEntry(
    name: String,
    dst: Option[Int] = None,
    src: Option[Int] = None,
    len: Option[Int] = None,
    alloc: Option[String] = None,
    free: Option[String] = None,
    untrustedRead: Option[Int] = None,
    untrustedCall: Boolean = false
  )

  private def decodeEntry(json: io.circe.Json): Option[MemApiEntry] =
      for
        name <- json.hcursor.get[String]("name").toOption
      yield MemApiEntry(
        name = name,
        dst = json.hcursor.get[Int]("dst").toOption,
        src = json.hcursor.get[Int]("src").toOption,
        len = json.hcursor.get[Int]("len").toOption,
        alloc = json.hcursor.get[String]("alloc").toOption,
        free = json.hcursor.get[String]("free").toOption,
        untrustedRead = json.hcursor.get[Int]("untrustedRead").toOption,
        untrustedCall = json.hcursor.get[Boolean]("untrustedCall").toOption.getOrElse(false)
      )

  /** @return
    *   the decoded entries, or a reason the document could not be read. The reason matters for an
    *   external config: a typo'd override that silently decoded to nothing would look exactly like
    *   a config that legitimately declares no APIs.
    */
  private def decodeApis(jsonStr: String): Either[String, List[MemApiEntry]] =
      parse(jsonStr).left.map(_.message).flatMap { json =>
          json.hcursor.downField("apis").as[List[io.circe.Json]] match
            case Right(entries) => Right(entries.flatMap(decodeEntry))
            case Left(err)      => Left(s"no readable `apis` array: ${err.message}")
      }

  private lazy val builtin: List[MemApiEntry] =
      Using(Source.fromResource(ResourcePath))(_.mkString).toOption.toList
          .flatMap(decodeApis(_).getOrElse(List.empty))

  /** The effective inventory: the built-in resource merged with the optional external config
    * (external entries win by name). Invalid external JSON is reported to stderr and ignored rather
    * than failing the whole analysis - a typo'd override must not disable tagging of the built-in
    * APIs.
    */
  def inventory(externalConfig: Option[String]): Map[String, MemApiEntry] =
    val external = externalConfig match
      case Some(jsonStr) =>
          decodeApis(jsonStr) match
            case Right(entries) => entries
            case Left(reason) =>
                System.err.println(s"warn: ignoring invalid memory-api config: $reason")
                List.empty
      case None => List.empty
    val merged = builtin.filterNot(b => external.exists(_.name == b.name)) ++ external
    merged.map(e => e.name -> e).toMap

  /** The built-in vocabulary, for tests and diagnostics. */
  def builtInInventory: List[MemApiEntry] = builtin
end MemApiVocab
