package io.appthreat.x2cpg.passes.taggers.js

/** The version each dependency resolved to, from the project's lockfile. All four npm-family
  * lockfiles are machine-generated in one stable shape, so these are small line readers over that
  * shape, not YAML/JSONC parsers.
  *
  * What a reader returns is every `(name, version)` the lockfile resolved; a name it resolves to
  * more than one version is not collapsed to a guess - the caller (`JsProject.resolvedVersions`)
  * drops it and reports it in `ambiguousVersions`.
  */
object JsLockfiles:

  /** A plain semver, nothing else: `1.2.3`, `1.2.3-beta.1`. A protocol (`patch:...`) or a workspace
    * stand-in (`0.0.0-use.local`, `*`) is not a resolution.
    */
  private val Semver = "(\\d+\\.\\d+\\.\\d+[\\w.+-]*|\\d+\\.\\d+|\\d+)".r

  private def isVersion(s: String): Boolean = Semver.findFirstIn(s).exists(_ == s)

  private val DependencyKeys =
      Seq("dependencies", "devDependencies", "optionalDependencies")

  /** The value of `key: value` or v1 yarn's `key "value"`. */
  private def valueAfterKey(line: String): String =
      if line.contains(':') then
        line.dropWhile(_ != ':').drop(1).trim.stripPrefix("\"").stripSuffix("\"")
      else line.trim.dropWhile(_ != ' ').drop(1).trim.stripPrefix("\"").stripSuffix("\"")

  /** A lockfile's `dependencies:`-style section, colon and all. */
  private def isDependencySection(t: String): Boolean =
      t.endsWith(":") && DependencyKeys.contains(t.stripSuffix(":"))

  def versionsOf(fileName: String, content: String): Seq[(String, String)] =
    val name =
        fileName.substring(math.max(fileName.lastIndexOf('/'), fileName.lastIndexOf('\\')) + 1)
    name match
      case "package-lock.json" => npm(content)
      case "yarn.lock"         => yarn(content)
      case "pnpm-lock.yaml"    => pnpm(content)
      case "bun.lock"          => bun(content)
      case _                   => Nil

  /** `package-lock.json`: v2/v3 `packages` (the root package is keyed `""`, a nested copy
    * `node_modules/a/node_modules/b`) and v1 `dependencies`.
    */
  private def npm(content: String): Seq[(String, String)] =
      io.circe.parser.parse(content).toOption.toList.flatMap { json =>
        val v2 = json.hcursor.downField("packages").as[Map[String, io.circe.Json]].toOption
            .toList.flatMap(_.toList.flatMap { (path, entry) =>
              val marker = path.lastIndexOf("node_modules/")
              if marker < 0 || path.indexOf("node_modules/") != marker then None
              else
                entry.hcursor.downField("version").as[String].toOption
                    .map(path.substring(marker + "node_modules/".length) -> _)
            })
        val v1 = json.hcursor.downField("dependencies").as[Map[String, io.circe.Json]].toOption
            .toList.flatMap(_.toList.flatMap((name, entry) =>
                entry.hcursor.downField("version").as[String].toOption.map(name -> _)
            ))
        v2 ++ v1
      }

  /** `yarn.lock`, v1 and berry: a block header of one or more `name@range` keys (berry's range
    * carries a protocol: `name@npm:^1.0.0`), the block naming the `version` it resolved. A key
    * whose range is `workspace:`, `patch:`, `link:`, `portal:` or `file:` names no registry
    * resolution.
    */
  private def yarn(content: String): Seq[(String, String)] =
    // (name -> version) found so far, and the names of the block being read, if it holds any
    case class Acc(found: List[(String, String)] = Nil, names: List[String] = Nil)
    content.linesIterator.foldLeft(Acc()) { (acc, line) =>
      val t = line.trim
      if t.isEmpty then acc.copy(names = Nil)
      else if line.startsWith(" ") || line.startsWith("\t") then
        if acc.names.nonEmpty && t.startsWith("version") then
          val v = valueAfterKey(t)
          if isVersion(v) then acc.copy(found = acc.names.map(_ -> v) ::: acc.found)
          else acc
        else acc
      else if t.endsWith(":") && t.contains('@') then
        // `"pkg@^1.0.0", "pkg@^1.2":` (v1) / `"pkg@npm:^1.0.0":` (berry) / `pkg@^1.0.0:`
        val names = t.stripSuffix(":").split(',').toList.flatMap { key =>
          val k     = key.trim.stripPrefix("\"").stripSuffix("\"")
          val at    = k.lastIndexOf('@')
          val range = if at > 0 then k.substring(at + 1) else ""
          val named = at > 0 && k.substring(0, at).nonEmpty
          Option.when(named && (range.isEmpty || !range.contains(':') || range.startsWith("npm:")))(
            k.substring(0, at)
          )
        }
        acc.copy(names = names)
      else acc.copy(names = Nil)
      end if
    }.found
  end yarn

  /** `pnpm-lock.yaml` v6 and v9: the version each workspace's dependencies resolved to, from
    * `importers:` (v9 and v6 workspaces) or the top-level `dependencies:` sections (a v6
    * single-package project). The `packages:` and `snapshots:` sections hold every hoisted copy,
    * not what an importer chose, so they are not read. A version may carry its resolved peers
    * (`5.2.0(prisma@5.2.0)`), which are not part of it.
    */
  private def pnpm(content: String): Seq[(String, String)] =
    // what the reader is inside: importers (a section per workspace), the top-level
    // dependency sections of a v6 single-package lock, or nothing
    enum Mode:
      case Importers, TopDeps, Outside
    case class Acc(
      mode: Mode = Mode.Outside,
      depsIndent: Int = -1,
      name: String = "",
      found: List[(String, String)] = Nil
    )
    content.linesIterator.foldLeft(Acc()) { (acc, line) =>
      val t      = line.trim
      val indent = line.indexWhere(_ != ' ')
      if t.isEmpty then acc
      else if indent == 0 then
        if t == "importers:" then acc.copy(mode = Mode.Importers, depsIndent = -1, name = "")
        else if isDependencySection(t) then acc.copy(mode = Mode.TopDeps, depsIndent = 0, name = "")
        else acc.copy(mode = Mode.Outside, depsIndent = -1, name = "")
      else if acc.mode == Mode.Outside then acc
      else if isDependencySection(t) then acc.copy(depsIndent = indent, name = "")
      else if acc.depsIndent < 0 || indent <= acc.depsIndent then acc
      else if t.endsWith(":") then
        // a dependency's name; `specifier: ^1.2.3` carries a value, so it is not this
        acc.copy(name =
            t.stripSuffix(":").stripPrefix("'").stripPrefix("\"").stripSuffix("'").stripSuffix("\"")
        )
      else if t.startsWith("version:") then
        val v = valueAfterKey(t).takeWhile(_ != '(')
        if acc.name.nonEmpty && isVersion(v) then
          acc.copy(name = "", found = (acc.name -> v) :: acc.found)
        else acc.copy(name = "")
      else acc // `specifier:`, `meta:` - the version line is what matters
    }.found
  end pnpm

  /** `bun.lock` (the text format): JSON with `//` comments and trailing commas. `packages` maps a
    * package name to `["name@resolvedVersion", ...]`; each workspace's dependencies name their
    * resolved version (`*` for a workspace link, which is no resolution).
    */
  private def bun(content: String): Seq[(String, String)] =
    val jsonc = content.linesIterator
        .filterNot(l => l.trim.startsWith("//"))
        .mkString("\n")
        .replaceAll(",(\\s*[}\\]])", "$1")
    io.circe.parser.parse(jsonc).toOption.toList.flatMap { json =>
      val fromPackages = json.hcursor.downField("packages").as[Map[String, io.circe.Json]]
          .toOption.toList.flatMap(_.toList.flatMap { (name, entry) =>
              entry.asArray.flatMap(_.headOption).flatMap(_.asString).flatMap { keyed =>
                val at = keyed.lastIndexOf('@')
                val v  = keyed.substring(at + 1)
                Option.when(at > 0 && isVersion(v))(name -> v)
              }
          })
      val fromWorkspaces = json.hcursor.downField("workspaces").as[Map[String, io.circe.Json]]
          .toOption.toList.flatMap(_.toList.flatMap((_, ws) =>
              DependencyKeys.flatMap(k =>
                  ws.hcursor.downField(k).as[Map[String, io.circe.Json]].toOption.toList
                      .flatMap(_.toList.flatMap((name, v) =>
                          v.asString.filter(isVersion).map(name -> _)
                      ))
              )
          ))
      fromPackages ++ fromWorkspaces
    }
  end bun
end JsLockfiles
