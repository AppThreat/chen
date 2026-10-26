package io.appthreat.x2cpg.passes.taggers.js

/** One resolution a lockfile records: a package's `name`, the manifest `range` it served where the
  * lockfile says (`^4.17.1` for `express@^4.17.1:`; npm's and bun's do not), and the `version` it
  * resolved to.
  */
final case class Resolution(name: String, range: Option[String], version: String)

/** The resolutions in a project's lockfiles. All four npm-family lockfiles are machine-generated in
  * one stable shape, so these are small line readers over that shape, not YAML/JSONC parsers.
  *
  * A reader returns every resolution it finds, the same one as often as the lockfile repeats it and
  * a name that resolved apart once per version; choosing the version a dependency of the project
  * resolved to is the caller's (`JsProject.resolvedVersions`).
  */
object JsLockfiles:

  /** The lockfile names the readers understand. */
  val FileNames: Set[String] = Set("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock")

  def baseName(path: String): String =
      path.substring(math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1)

  /** A plain semver, nothing else: `1.2.3`, `1.2.3-beta.1`. A protocol (`patch:...`) or a stand-in
    * (`*`) is not a resolution.
    */
  private val Semver = "(\\d+\\.\\d+\\.\\d+[\\w.+-]*|\\d+\\.\\d+|\\d+)".r

  private def isVersion(s: String): Boolean = Semver.findFirstIn(s).exists(_ == s)

  private val DependencyKeys =
      Seq("dependencies", "devDependencies", "optionalDependencies")

  private def unquote(s: String): String =
      s.trim.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")

  /** The value of `key: value` or v1 yarn's `key "value"`. */
  private def valueAfterKey(line: String): String =
      if line.contains(':') then unquote(line.dropWhile(_ != ':').drop(1))
      else unquote(line.trim.dropWhile(_ != ' '))

  /** A lockfile's `dependencies:`-style section, colon and all. */
  private def isDependencySection(t: String): Boolean =
      t.endsWith(":") && DependencyKeys.contains(t.stripSuffix(":"))

  private def indentOf(line: String): Int = line.indexWhere(_ != ' ')

  def resolutionsOf(fileName: String, content: String): Seq[Resolution] =
      baseName(fileName) match
        case "package-lock.json" => npm(content)
        case "yarn.lock"         => yarn(content)
        case "pnpm-lock.yaml"    => pnpm(content)
        case "bun.lock"          => bun(content)
        case _                   => Nil

  /** `package-lock.json`: v2/v3 `packages` (the root package is keyed `""`, a nested copy
    * `node_modules/a/node_modules/b`, which is not what the project resolved) and v1
    * `dependencies`. A v2 lockfile carries both, naming each top-level version twice.
    */
  private def npm(content: String): Seq[Resolution] =
      io.circe.parser.parse(content).toOption.toList.flatMap { json =>
        val v2 = json.hcursor.downField("packages").as[Map[String, io.circe.Json]].toOption
            .toList.flatMap(_.toList.flatMap { (path, entry) =>
              val marker = path.lastIndexOf("node_modules/")
              if marker < 0 || path.indexOf("node_modules/") != marker then None
              else
                entry.hcursor.downField("version").as[String].toOption.filter(isVersion)
                    .map(Resolution(path.substring(marker + "node_modules/".length), None, _))
            })
        val v1 = json.hcursor.downField("dependencies").as[Map[String, io.circe.Json]].toOption
            .toList.flatMap(_.toList.flatMap((name, entry) =>
                entry.hcursor.downField("version").as[String].toOption.filter(isVersion)
                    .map(Resolution(name, None, _))
            ))
        v2 ++ v1
      }

  /** A yarn block key: `pkg@^1.0.0` (v1) or `pkg@npm:^1.0.0` (berry), scoped names included. A key
    * whose range is `workspace:`, `patch:`, `link:`, `portal:`, `file:`, a URL or a git ref names
    * no registry resolution, and an alias (`string-width-cjs@npm:string-width@^4.2.0`) names a
    * package other than its key: neither is a resolution of the key's name.
    */
  private def yarnKey(key: String): Option[(String, String)] =
    val k  = unquote(key)
    val at = k.indexOf('@', 1)
    if at <= 0 then None
    else
      val range = k.substring(at + 1).stripPrefix("npm:")
      Option.when(!range.contains(':') && !range.contains('@'))(k.substring(0, at) -> range)

  /** `yarn.lock`, v1 and berry: a block header of one or more keys, the block's own two-space
    * indented `version` field naming what they resolved to. Deeper lines (a block's
    * `dependencies:`) are not the block's version even when a dependency is named `version...`.
    */
  private def yarn(content: String): Seq[Resolution] =
    // the resolutions found so far, and the (name, range) keys of the block being read
    case class Acc(found: List[Resolution] = Nil, keys: List[(String, String)] = Nil)
    content.linesIterator.foldLeft(Acc()) { (acc, line) =>
      val t = line.trim
      if t.isEmpty then acc.copy(keys = Nil)
      else if indentOf(line) == 2 then
        if acc.keys.nonEmpty && (t.startsWith("version ") || t.startsWith("version:")) then
          val v = valueAfterKey(t)
          if isVersion(v) then
            acc.copy(found = acc.keys.map((n, r) => Resolution(n, Some(r), v)) ::: acc.found)
          else acc
        else acc
      else if indentOf(line) > 2 then acc
      else if t.endsWith(":") && t.contains('@') then
        acc.copy(keys = t.stripSuffix(":").split(',').toList.flatMap(yarnKey))
      else acc.copy(keys = Nil)
    }.found

  /** `pnpm-lock.yaml`: the version each workspace's dependencies resolved to, from `importers:`
    * (v9, and v5/v6 workspaces) or the top-level `dependencies:` sections (a v5/v6 single-package
    * project). v6 and v9 give each dependency a `specifier` (its manifest range) and a `version`;
    * v5 writes `name: version` inline and keeps the ranges in a separate `specifiers:` section,
    * which is not read. The `packages:` and `snapshots:` sections hold every hoisted copy, not what
    * an importer chose, so they are not read either. A version may carry its resolved peers
    * (`5.2.0(prisma@5.2.0)`, v5's `5.2.0_prisma@5.2.0`), which are not part of it.
    */
  private def pnpm(content: String): Seq[Resolution] =
    def bare(v: String): String = v.takeWhile(c => c != '(' && c != '_')
    // whether the reader is inside importers or the top-level dependency sections; the indent of
    // the dependency section being read and of its names; the name and specifier being read
    case class Acc(
      inside: Boolean = false,
      depsIndent: Int = -1,
      nameIndent: Int = -1,
      name: String = "",
      specifier: Option[String] = None,
      found: List[Resolution] = Nil
    ):
      def enter(indent: Int): Acc =
          copy(depsIndent = indent, nameIndent = -1, name = "", specifier = None)
    content.linesIterator.foldLeft(Acc()) { (acc, line) =>
      val t      = line.trim
      val indent = indentOf(line)
      if t.isEmpty || t.startsWith("#") then acc
      else if indent == 0 then
        if t == "importers:" then Acc(inside = true, found = acc.found)
        else if isDependencySection(t) then Acc(inside = true, found = acc.found).enter(0)
        else Acc(found = acc.found)
      else if !acc.inside then acc
      else if isDependencySection(t) then acc.enter(indent)
      else if acc.depsIndent < 0 || indent <= acc.depsIndent then
        // an importer's key or another of its sections (`specifiers:`, `dependenciesMeta:`)
        acc.copy(depsIndent = -1)
      else if acc.nameIndent < 0 || indent == acc.nameIndent then
        val withIndent = acc.copy(nameIndent = indent, name = "", specifier = None)
        if t.endsWith(":") then withIndent.copy(name = unquote(t.stripSuffix(":")))
        else
          // v5: `express: 4.18.2`
          val colon = t.indexOf(": ")
          val v     = if colon > 0 then bare(unquote(t.substring(colon + 2))) else ""
          if isVersion(v) then
            withIndent.copy(found =
                Resolution(unquote(t.substring(0, colon)), None, v) :: acc.found
            )
          else withIndent
      else if t.startsWith("specifier:") then acc.copy(specifier = Some(valueAfterKey(t)))
      else if t.startsWith("version:") then
        val v = bare(valueAfterKey(t))
        if acc.name.nonEmpty && isVersion(v) then
          acc.copy(found = Resolution(acc.name, acc.specifier, v) :: acc.found)
        else acc
      else acc
      end if
    }.found
  end pnpm

  /** `bun.lock` (the text format): JSON with `//` comments and trailing commas. `packages` maps a
    * package to `["name@resolvedVersion", ...]`; the hoisted copy, the one a project's own
    * dependency resolves to, is keyed by the package name (`react`, `@types/node`), a nested copy
    * by its path (`@babel/core/semver`).
    */
  private def bun(content: String): Seq[Resolution] =
    def isPackageName(key: String): Boolean =
        key.count(_ == '/') == (if key.startsWith("@") then 1 else 0)
    val jsonc = content.linesIterator
        .filterNot(l => l.trim.startsWith("//"))
        .mkString("\n")
        .replaceAll(",(\\s*[}\\]])", "$1")
    io.circe.parser.parse(jsonc).toOption.toList.flatMap { json =>
        json.hcursor.downField("packages").as[Map[String, io.circe.Json]].toOption.toList
            .flatMap(_.toList.flatMap { (key, entry) =>
                entry.asArray.flatMap(_.headOption).flatMap(_.asString).flatMap { keyed =>
                  val at = keyed.lastIndexOf('@')
                  val v  = keyed.substring(at + 1)
                  Option.when(isPackageName(key) && at > 0 && isVersion(v))(
                    Resolution(keyed.substring(0, at), None, v)
                  )
                }
            })
    }
  end bun
end JsLockfiles
