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
  *
  * Beside the per-API inventory, the same resource declares LIBRARY PROFILES (`{"profiles":
  * [...]}`, see [[MemApiProfile]]): the memory management of one library, whose declarations live
  * in headers outside the analysed tree so that no body can be inferred from. A profile is selected
  * for a translation unit that includes one of its headers ([[selectProfiles]]); an external config
  * can add or replace profiles the same way it replaces API entries.
  */
object MemApiVocab:

  final val ResourcePath = "memory-apis.json"

  /** A (buffer member, capacity member) pair of one struct type: reads through `type *p`'s member
    * `buffer` are bounded by `p->capacity`. AVPacket's data/size is the canonical pair; a type
    * whose definition is outside the analysed tree cannot resolve its members on the graph, so the
    * pair is declared instead. External config only, next to the API entries:
    * {{{
    * "bufferExtents": [{"type": "AVPacket", "buffer": "data", "capacity": "size"}]
    * }}}
    */
  final case class BufferExtent(typeName: String, buffer: String, capacity: String)

  /** The region role a profile entry declares for its call, in the shape the resource states:
    * {{{
    * {"role": "create" | "allocate" | "reset" | "destroy", "arg": <index>}
    * {"role": "allocate", "context": "<global name>"}
    * }}}
    *
    * `arg` is the 1-based index of the argument that IS the region: the owning device of
    * `devm_kzalloc(dev, ...)`, the pool of `apr_palloc(pool, ...)`, the context a reset empties or
    * a destroy tears down. `context` names the global a context-less allocate draws from,
    * PostgreSQL's `CurrentMemoryContext`. `create` names no `context`: its `arg`, when present, is
    * the out-pointer argument the created region is stored through (`apr_pool_create(&pool,
    * parent)` hands the new pool out through argument 1), and with no `arg` the region is the
    * call's result.
    */
  final case class MemRegion(role: String, arg: Option[Int] = None, context: Option[String] = None)

  object MemRegion:
    val Roles = Set("create", "allocate", "reset", "destroy")

  /** A library's memory management, declared for translation units that include one of `headers`
    * (matched by basename: `linux/slab.h` in the list selects for an `slab.h` include). Entries
    * have the inventory's shape plus the declared-only roles and a `source` citation each: the
    * header or documentation page that states the behaviour, since the declarations sit in headers
    * outside the analysed tree and no body inference can confirm them.
    */
  final case class MemApiProfile(name: String, headers: List[String], entries: List[MemApiEntry])

  /** A memory API and the roles of its arguments. Indices are 1-based argument positions.
    *
    * @param dst
    *   argument the API writes its result into (the copy destination).
    * @param src
    *   argument the copied/read data comes from.
    * @param len
    *   argument that bounds the operation in BYTES (byte count, element size, capacity).
    * @param count
    *   element-count argument of a count-by-size allocator (`calloc(nmemb, size)`): the size that
    *   can overflow is the PRODUCT, so the count joins `len` as a tagged length role and the
    *   overflow question can be asked about either factor. Absent for single-size allocators.
    * @param alloc
    *   allocation family of the call (`heap`, `new`, `new[]`, `mmap`, `file` for a `FILE *` stream,
    *   `fd` for an integer descriptor). The family a release must match. A config that still names
    *   the descriptor family `socket`, its name before sockets and files shared one, is read as
    *   `fd`.
    * @param free
    *   release family of the call: the family of the blocks it releases. JSON `"free": "heap"`, or
    *   a list for a release that accepts blocks of several families (`kvfree` takes `kmalloc`,
    *   `vmalloc` and `kvmalloc` memory: `"free": ["slab", "vmalloc", "kvmalloc"]`); the first is
    *   this field and the rest are `alsoFrees`.
    * @param alsoFrees
    *   the further families a release accepts, beyond `free`.
    * @param realloc
    *   the third family: the call releases its input pointer AND returns a fresh allocation
    *   (`realloc`, `av_reallocp_array`). Carried SEPARATELY from `alloc`/`free` because every
    *   consumer reads those two as disjoint sets, and a realloc is honestly neither: it does not
    *   leave the input valid (not a pure allocation) and it yields a new pointer (not a pure
    *   release).
    * @param untrustedRead
    *   argument the API fills with untrusted data (the buffer a `read`/`recv`/`fgets` fills).
    * @param untrustedCall
    *   true when the call's result or variadic outputs are untrusted but no single buffer argument
    *   exists (`getenv`, the scanf family).
    * @param clamp
    *   when the API is a clamping macro/helper: `min` (result bounded above by each argument),
    *   `max` (bounded below) or `clip` (arg2 below, arg3 above). This is how an UNEXPANDED
    *   `FFMIN`-style call still establishes a bound in GuardPass - the same declared-vocabulary
    *   route the flow semantics use, so a project's own `MYMIN` is a data change.
    * @param nullableReturn
    *   true when the call's result may be NULL: pointer-returning allocators and the
    *   `strchr`/`strstr` family's no-match NULL. Declared per entry, never implied by the family -
    *   an fd-returning allocator fails with -1, not NULL. [[MemoryApiPass]] emits `nullable-return`
    *   for it.
    * @param returnRange
    *   the closed range the call's result always lies in, `[lo, hi]` - `fgetc` is `[-1, 255]`,
    *   FFmpeg's `avio_r8` `[0, 255]`. JSON `"returnRange": [0, 255]`. The index rules' value ranges
    *   read it ([[MemoryApiPass.TagReturnRange]]); a reader that can return a negative error code
    *   must say so in its range or not be declared.
    * @param returnBits
    *   the argument whose integer literal is the result's width in bits: `get_bits(gb, 4)` is `[0,
    *   15]` with `"returnBits": 2`. A call whose width argument is not a literal gets no range.
    * @param increments
    *   the argument and struct field a call grows by one: `avformat_new_stream(s, c)` increments
    *   `s->nb_streams`. JSON `"increments": {"arg": 1, "field": "nb_streams"}`. The counter's
    *   definitions sit inside the callee, so no in-method walk can find them; a callee whose body
    *   is in the tree is inferred instead ([[MemorySemanticsPass]]).
    * @param readsFrom
    *   the first argument position the call READS THROUGH, and every position after it: the printf
    *   family's variadic tail (`printf(f, p, q)` reads p and q). A `nonRetaining` entry without
    *   read positions would hand its arguments to nobody - the use questions (a freed or
    *   possibly-null pointer printed) read the positions this declares.
    * @param api
    *   the API this entry is a spelling of, when that is another entry: a FORTIFY wrapper
    *   (`__memcpy_chk`) or a compiler builtin (`__builtin_memcpy`) is `memcpy`. Tags are valued
    *   with it, so a rule reads the wrapper's arguments exactly as the API's.
    * @param objectSize
    *   the argument a FORTIFY wrapper receives the destination's size in, as the compiler worked it
    *   out (`(size_t)-1` when it could not).
    * @param release
    *   the 1-based parameter the call releases, a PROFILE-declared role: a reference count it
    *   decrements, freeing or destroying the object when the count reaches zero. The index names
    *   the released OBJECT's argument: `kref_put(&o->refs, release_cb)` releases the object reached
    *   through argument 1, while the release callback it calls at zero is argument 2.
    * @param acquire
    *   the parameter whose reference the call acquires (increments): `Py_INCREF(op)`.
    * @param retains
    *   the 1-based parameter whose resource the call takes over: what the call returns owns it, and
    *   releasing the result releases it too. `fdopen(fd, mode)` retains argument 1, the descriptor
    *   the stream's `fclose` then closes.
    * @param steal
    *   the pointer-to-pointer parameter the call empties: it reads `*pp`, stores NULL and returns
    *   the value it read, `g_steal_pointer(&p)`.
    * @param cleanup
    *   true when the call takes the address of a variable and releases what it points to (the
    *   function a cleanup attribute runs at scope exit).
    * @param region
    *   the region role the call plays in its library's pool or context scheme, see [[MemRegion]].
    * @param source
    *   where the entry's behaviour is stated: the header (and line) or documentation page a
    *   maintainer can check it against. Provenance for humans; no consumer reads it.
    */
  final case class MemApiEntry(
    name: String,
    dst: Option[Int] = None,
    src: Option[Int] = None,
    len: Option[Int] = None,
    count: Option[Int] = None,
    alloc: Option[String] = None,
    free: Option[String] = None,
    alsoFrees: List[String] = Nil,
    realloc: Option[String] = None,
    untrustedRead: Option[Int] = None,
    untrustedCall: Boolean = false,
    clamp: Option[String] = None,
    nullableReturn: Boolean = false,
    returnRange: Option[(BigInt, BigInt)] = None,
    returnBits: Option[Int] = None,
    increments: Option[(Int, String)] = None,
    api: Option[String] = None,
    objectSize: Option[Int] = None,
    nonRetaining: Boolean = false,
    readsFrom: Option[Int] = None,
    release: Option[Int] = None,
    acquire: Option[Int] = None,
    retains: Option[Int] = None,
    steal: Option[Int] = None,
    cleanup: Boolean = false,
    region: Option[MemRegion] = None,
    source: Option[String] = None
  ):
    /** The API name the entry's tags are valued with. */
    def apiName: String = api.getOrElse(name)

    /** Every family the call releases: [[free]] and [[alsoFrees]]. */
    def freeFamilies: List[String] = free.toList ++ alsoFrees
  end MemApiEntry

  /** A 1-based parameter index the format declares for a role: absent means the role is not
    * declared; present but not a positive whole JSON number is malformed and drops the entry (a
    * quoted number is a string, not an index).
    */
  private def paramIndex(json: io.circe.Json, field: String): Either[String, Option[Int]] =
      json.hcursor.downField(field).focus match
        case None => Right(None)
        case Some(v) if v.isNumber =>
            v.as[Int].toOption match
              case Some(i) if i >= 1 => Right(Some(i))
              case _ => Left(s"`$field` must be a parameter index (a number 1 or greater)")
        case Some(_) =>
            Left(s"`$field` must be a parameter index (a number 1 or greater)")

  /** A declared boolean flag: absent is false, present but not a JSON boolean is malformed. */
  private def booleanFlag(json: io.circe.Json, field: String): Either[String, Boolean] =
      json.hcursor.downField(field).focus match
        case None                   => Right(false)
        case Some(v) if v.isBoolean => Right(v.asBoolean.get)
        case Some(_)                => Left(s"`$field` must be true or false")

  private def sourceOf(json: io.circe.Json): Either[String, Option[String]] =
      json.hcursor.downField("source").focus match
        case None => Right(None)
        case Some(v) =>
            v.as[String].toOption match
              case Some(s) if s.trim.nonEmpty => Right(Some(s))
              case _ =>
                  Left(
                    s"`source` must be a non-empty string naming where the behaviour is stated"
                  )

  private def regionOf(json: io.circe.Json): Either[String, Option[MemRegion]] =
      json.hcursor.downField("region").focus match
        case None => Right(None)
        case Some(v) =>
            def malformed(why: String): String = s"`region` $why"
            def indexField(a: io.circe.Json, why: String): Either[String, Int] =
                if a.isNumber then a.as[Int].toOption.filter(_ >= 1).toRight(why) else Left(why)
            for
              obj <-
                  v.as[Map[String, io.circe.Json]].toOption.toRight(
                    malformed("must be an object")
                  )
              role <-
                  obj.get("role").flatMap(_.as[String].toOption).toRight(
                    malformed("needs a `role` string")
                  )
              _ <-
                  Either.cond(
                    MemRegion.Roles.contains(role),
                    (),
                    malformed(
                      s"has unknown role `$role`, expected one of ${MemRegion.Roles.mkString(", ")}"
                    )
                  )
              arg <-
                  obj.get("arg") match
                    case None => Right(None)
                    case Some(a) =>
                        indexField(
                          a,
                          malformed("`arg` must be a parameter index (a number 1 or greater)")
                        ).map(Some(_))
              ctx <-
                  obj.get("context") match
                    case None => Right(None)
                    case Some(c) =>
                        c.as[String].toOption
                            .filter(_.nonEmpty)
                            .map(Some(_))
                            .toRight(malformed(
                              "`context` must be a non-empty string naming the global"
                            ))
              region <-
                  (role, arg, ctx) match
                    case ("allocate", Some(a), None) => Right(MemRegion(role, arg = Some(a)))
                    case ("allocate", None, Some(c)) => Right(MemRegion(role, context = Some(c)))
                    case ("allocate", _, _) =>
                        Left(
                          malformed(
                            "`allocate` needs exactly one of `arg` (the region argument) or " +
                                "`context` (the global it draws from)"
                          )
                        )
                    case ("create", a, None) => Right(MemRegion(role, arg = a))
                    case ("create", _, Some(_)) =>
                        Left(malformed(
                          "`create` takes no `context`: the region is the call's result"
                        ))
                    case (_, None, _)       => Left(malformed(s"`$role` needs the region in `arg`"))
                    case (_, _, Some(_))    => Left(malformed(s"`$role` takes no `context`"))
                    case (_, Some(a), None) => Right(MemRegion(role, arg = Some(a)))
            yield Some(region)
            end for
  /** Everything but the entry's name, which only qualifies the error message. The long-standing
    * fields stay silently forgiving (a wrong shape loses the field, as before); the declared-role
    * fields are validated because they state behaviour nothing in the analysed tree can confirm.
    */
  private def decodeRoles(json: io.circe.Json): Either[String, MemApiEntry] =
      for
        release <- paramIndex(json, "release")
        acquire <- paramIndex(json, "acquire")
        retains <- paramIndex(json, "retains")
        steal   <- paramIndex(json, "steal")
        cleanup <- booleanFlag(json, "cleanup")
        region  <- regionOf(json)
        source  <- sourceOf(json)
      yield MemApiEntry(
        name = "",
        dst = json.hcursor.get[Int]("dst").toOption,
        src = json.hcursor.get[Int]("src").toOption,
        len = json.hcursor.get[Int]("len").toOption,
        count = json.hcursor.get[Int]("count").toOption,
        alloc = json.hcursor.get[String]("alloc").toOption.map(currentFamily),
        free = freesOf(json).headOption,
        alsoFrees = freesOf(json).drop(1),
        realloc = json.hcursor.get[String]("realloc").toOption.map(currentFamily),
        untrustedRead = json.hcursor.get[Int]("untrustedRead").toOption,
        untrustedCall = json.hcursor.get[Boolean]("untrustedCall").toOption.getOrElse(false),
        clamp = json.hcursor.get[String]("clamp").toOption,
        nullableReturn = json.hcursor.get[Boolean]("nullableReturn").toOption.getOrElse(false),
        returnRange = json.hcursor.get[List[BigInt]]("returnRange").toOption.collect {
            case List(lo, hi) if lo <= hi => (lo, hi)
        },
        returnBits = json.hcursor.get[Int]("returnBits").toOption,
        increments =
            for
              obj <- json.hcursor.downField("increments").as[Map[String, io.circe.Json]].toOption
              arg <- obj.get("arg").flatMap(_.as[Int].toOption)
              fld <- obj.get("field").flatMap(_.as[String].toOption)
              if arg >= 1 && fld.nonEmpty
            yield (arg, fld),
        api = json.hcursor.get[String]("api").toOption.filter(_.nonEmpty),
        objectSize = json.hcursor.get[Int]("objectSize").toOption,
        nonRetaining = json.hcursor.get[Boolean]("nonRetaining").toOption.getOrElse(false),
        readsFrom = json.hcursor.get[Int]("readsFrom").toOption,
        release = release,
        acquire = acquire,
        retains = retains,
        steal = steal,
        cleanup = cleanup,
        region = region,
        source = source
      )

  /** The family a config's spelling names today: `socket`, the descriptor family's name before
    * sockets and files shared it, is `fd`.
    */
  private def currentFamily(family: String): String =
      if family == "socket" then "fd" else family

  /** An entry's `free` families: one string, or a list of them. */
  private def freesOf(json: io.circe.Json): List[String] =
    val cursor = json.hcursor.downField("free")
    cursor.as[String].toOption.map(List(_))
        .orElse(cursor.as[List[String]].toOption)
        .getOrElse(Nil)
        .filter(_.nonEmpty)
        .map(currentFamily)
        .distinct

  private def decodeEntry(json: io.circe.Json): Either[String, MemApiEntry] =
      for
        name <-
            json.hcursor.get[String]("name").toOption.filter(_.nonEmpty).toRight(
              "an entry needs a non-empty `name` string"
            )
        entry <- decodeRoles(json).left.map(reason => s"entry `$name`: $reason")
      yield entry.copy(name = name)

  /** An unreadable element of a config is dropped with a note on stderr rather than failing the
    * whole analysis - the same trade an invalid external config makes.
    */
  private def dropWithNote[A](decoded: Either[String, A], what: String): Option[A] =
      decoded match
        case Right(value) => Some(value)
        case Left(reason) =>
            System.err.println(s"warn: dropping $what: $reason")
            None

  /** @return
    *   the decoded entries, or a reason the document could not be read. The reason matters for an
    *   external config: a typo'd override that silently decoded to nothing would look exactly like
    *   a config that legitimately declares no APIs.
    */
  private def decodeApis(jsonStr: String): Either[String, List[MemApiEntry]] =
      parse(jsonStr).left.map(_.message).flatMap { json =>
          json.hcursor.downField("apis").as[List[io.circe.Json]] match
            case Right(entries) =>
                Right(entries.flatMap(e => dropWithNote(decodeEntry(e), "memory-api entry")))
            // a config that only declares profiles has no API entries to read
            case Left(_)
                if json.hcursor.downField("apis").focus.isEmpty &&
                    json.hcursor.downField("profiles").focus.isDefined =>
                Right(Nil)
            case Left(err) => Left(s"no readable `apis` array: ${err.message}")
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
    withBuiltinSpellings(merged.map(e => e.name -> e).toMap)

  /** The compiler builtin `__builtin_X` of every entry X that is a function: the same arguments and
    * roles, valued as X. An entry that declares the builtin itself keeps its own roles.
    */
  private def withBuiltinSpellings(entries: Map[String, MemApiEntry]): Map[String, MemApiEntry] =
      entries ++ entries.values.collect {
          case e if !e.name.startsWith("<") && !entries.contains(BuiltinPrefix + e.name) =>
              (BuiltinPrefix + e.name) -> e.copy(
                name = BuiltinPrefix + e.name,
                api = Some(e.apiName)
              )
      }

  private final val BuiltinPrefix = "__builtin_"

  private def decodeProfile(json: io.circe.Json): Either[String, MemApiProfile] =
    val nameOpt = json.hcursor.get[String]("name").toOption.filter(_.nonEmpty)
    def named(reason: String): String =
        nameOpt.map(n => s"profile `$n`: $reason").getOrElse(reason)
    for
      name <- nameOpt.toRight("a profile needs a non-empty `name` string")
      headers <-
          json.hcursor.get[List[String]]("headers").toOption
              .map(_.filter(_.nonEmpty))
              .filter(_.nonEmpty)
              .toRight(named("needs a non-empty `headers` array"))
      entryJsons <-
          json.hcursor.downField("entries").as[List[io.circe.Json]].toOption.toRight(
            named("needs a readable `entries` array")
          )
      // every profile entry must say where its behaviour is stated, or the citation that makes
      // the declared roles checkable is silently lost
      entries = entryJsons.flatMap { entryJson =>
          dropWithNote(
            decodeEntry(entryJson).filterOrElse(
              e => e.source.exists(_.trim.nonEmpty),
              s"entry `${entryJson.hcursor.get[String]("name").toOption.getOrElse("??")}`: a profile entry needs a `source` citation"
            ),
            "memory-api entry"
          )
      }
    yield MemApiProfile(name, headers, entries)
    end for
  end decodeProfile

  private def decodeProfiles(json: io.circe.Json): Either[String, List[MemApiProfile]] =
      json.hcursor.downField("profiles").as[List[io.circe.Json]] match
        case Right(profiles) =>
            Right(profiles.flatMap(p => dropWithNote(decodeProfile(p), "memory-api profile")))
        case Left(err) => Left(s"no readable `profiles` array: ${err.message}")

  private lazy val builtinProfiles: List[MemApiProfile] =
      Using(Source.fromResource(ResourcePath))(_.mkString).toOption.toList.flatMap { text =>
          parse(text).toOption.toList.flatMap(decodeProfiles(_).getOrElse(List.empty))
      }

  /** The declared library profiles, by name: the built-in resource's `profiles` array with an
    * external config's `profiles` array merged over it by profile name (an external profile
    * replaces a same-named built-in one wholesale, the way an external entry replaces a built-in
    * API entry). An external config that declares no profiles changes nothing; one whose `profiles`
    * value is unreadable is reported to stderr and ignored, like an unreadable `apis` array.
    */
  def profiles(externalConfig: Option[String]): Map[String, MemApiProfile] =
    val external = externalConfig.toList.flatMap { jsonStr =>
        parse(jsonStr) match
          case Right(json) if json.hcursor.downField("profiles").focus.isDefined =>
              decodeProfiles(json) match
                case Right(profiles) => profiles
                case Left(reason) =>
                    System.err.println(s"warn: ignoring invalid memory-api profiles: $reason")
                    List.empty
          case _ => List.empty
    }
    val merged = builtinProfiles.filterNot(b => external.exists(_.name == b.name)) ++ external
    merged.map(p => p.name -> p).toMap

  private def basename(header: String): String =
      header.substring(math.max(header.lastIndexOf('/'), header.lastIndexOf('\\')) + 1)

  /** The profiles a translation unit selects, given the headers it includes: a profile whose header
    * list contains one of them, compared by basename on both sides (a profile declares
    * `linux/slab.h`, a unit records the `slab.h` it includes), is selected. A unit that includes no
    * listed header selects nothing.
    */
  def selectProfiles(
    externalConfig: Option[String],
    includedHeaders: Set[String]
  ): Map[String, MemApiProfile] =
    val included = includedHeaders.map(basename)
    profiles(externalConfig).filter { case (_, profile) =>
        profile.headers.map(basename).exists(included.contains)
    }

  private lazy val builtinInventory: Map[String, MemApiEntry] = inventory(None)

  /** The API a call name spells: `memcpy` for `__builtin_memcpy`, `__memcpy_chk` and
    * `__builtin___memcpy_chk`; the name itself when it spells no other entry.
    */
  def apiOf(callName: String): String =
      builtinInventory.get(callName).map(_.apiName).getOrElse(callName)

  /** The prefixes of input functions no single entry can list: a verification benchmark's
    * `nondet_*` and `__VERIFIER_nondet_*` return the program's input. A call so named is an
    * untrusted call.
    */
  lazy val untrustedPrefixes: List[String] =
      Using(Source.fromResource(ResourcePath))(_.mkString).toOption.toList.flatMap { text =>
          parse(text).toOption.toList.flatMap(
            _.hcursor.downField("untrustedPrefixes").as[List[String]].toOption.getOrElse(Nil)
          )
      }

  /** The built-in vocabulary, for tests and diagnostics. */
  def builtInInventory: List[MemApiEntry] = builtin

  /** The declared (buffer member, capacity member) pairs, by struct type name. The built-in
    * resource declares none - a project's types are the external config's to name.
    */
  def bufferExtents(externalConfig: Option[String]): Map[String, (String, String)] =
      externalConfig match
        case Some(jsonStr) =>
            parse(jsonStr) match
              case Right(json) =>
                  json.hcursor.downField("bufferExtents").as[List[io.circe.Json]].toOption
                      .getOrElse(Nil).flatMap { e =>
                          for
                            t <- e.hcursor.get[String]("type").toOption
                            b <- e.hcursor.get[String]("buffer").toOption
                            c <- e.hcursor.get[String]("capacity").toOption
                            if t.nonEmpty && b.nonEmpty && c.nonEmpty
                          yield t -> ((b, c))
                      }.toMap
              case Left(_) => Map.empty
        case None => Map.empty
end MemApiVocab
