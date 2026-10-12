package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** Module specifiers that name a project file without being relative: path aliases.
  *
  * A project imports its own modules through aliases as often as through relative paths - Next.js
  * and Vite starters through `@/…`, Nuxt, Remix, SolidStart and TanStack Start through `~/…`,
  * SvelteKit through `$lib/…`, an Ember app through its own package name (`docs-app/components/…`).
  * Unresolved, every such import looks like an npm package: the calls it binds reach nothing and
  * the components it names are not the project's.
  *
  * Resolved, in order:
  *   - `compilerOptions.paths` (with `baseUrl`) of the nearest `tsconfig.json`/`jsconfig.json`
  *     above the importing file;
  *   - the nearest `package.json`'s own name with its `exports` subpath patterns (an Ember app maps
  *     every subpath to `./app/`), and its `#` `imports`;
  *   - the conventions the frameworks' starters use: `@/` and `~/` for `src/`, `app/` or the
  *     project root, `~~/` and `@@/` for the root, `$lib/` for `src/lib/`.
  *
  * A candidate counts only when a project file is there; the result is the file's path - without
  * its extension unless the specifier names one, or the directory of an `index` file - as a
  * relative specifier resolves.
  */
final class JsPathAliases(cpg: Cpg):

  private val ScriptExtensions =
      Seq(
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".mts",
        ".cjs",
        ".cts",
        ".vue",
        ".svelte",
        ".astro",
        ".gjs",
        ".gts"
      )

  private def normalize(path: String): String =
    val parts = scala.collection.mutable.ArrayBuffer.empty[String]
    path.replace('\\', '/').split("/").foreach {
        case "" | "." =>
        case ".."     => if parts.nonEmpty then parts.trimEnd(1)
        case part     => parts += part
    }
    parts.mkString("/")

  private def dirOf(path: String): String =
    val p = path.replace('\\', '/')
    if p.contains('/') then p.substring(0, p.lastIndexOf('/')) else ""

  private def join(dir: String, rest: String): String =
      normalize(if dir.isEmpty then rest else s"$dir/$rest")

  /** Every project file's path without its extension, and the directory of each `index` file. */
  private lazy val bases: Set[String] =
      cpg.file.name.l.map(_.replace('\\', '/')).flatMap { f =>
        val ext  = ScriptExtensions.find(f.endsWith)
        val base = ext.map(e => f.dropRight(e.length)).getOrElse(f)
        val asIs = Seq(f, base)
        if base.endsWith("/index") then asIs :+ base.dropRight("/index".length) else asIs
      }.toSet

  /** Config files by kind: (directory, parsed JSON). */
  private def configs(names: String*): List[(String, io.circe.Json)] =
      cpg.configFile.l
          .filter(f =>
            val n = f.name.replace('\\', '/')
            names.exists(k => n == k || n.endsWith(s"/$k")) && !n.contains("node_modules")
          )
          .flatMap(f => parseJsonc(f.content).map(dirOf(f.name) -> _))
          .sortBy(-_._1.length)

  /** JSON with comments and trailing commas, as tsconfig files are written. */
  private def parseJsonc(text: String): Option[io.circe.Json] =
    val out      = new StringBuilder
    var i        = 0
    var inString = false
    while i < text.length do
      val c = text.charAt(i)
      if inString then
        out.append(c)
        if c == '\\' && i + 1 < text.length then
          out.append(text.charAt(i + 1))
          i += 1
        else if c == '"' then inString = false
        i += 1
      else if c == '"' then
        inString = true
        out.append(c)
        i += 1
      else if c == '/' && i + 1 < text.length && text.charAt(i + 1) == '/' then
        while i < text.length && text.charAt(i) != '\n' do i += 1
      else if c == '/' && i + 1 < text.length && text.charAt(i + 1) == '*' then
        val end = text.indexOf("*/", i + 2)
        i = if end < 0 then text.length else end + 2
      else
        out.append(c)
        i += 1
    end while
    io.circe.parser.parse(out.toString.replaceAll(",(\\s*[}\\]])", "$1")).toOption
  end parseJsonc

  /** `paths` patterns of each tsconfig/jsconfig: (config dir, base dir, pattern, targets). */
  private lazy val pathPatterns: List[(String, String, String, List[String])] =
      configs("tsconfig.json", "jsconfig.json").flatMap { (dir, json) =>
        val options = json.hcursor.downField("compilerOptions")
        val baseUrl = options.downField("baseUrl").as[String].toOption.getOrElse(".")
        options.downField("paths").as[Map[String, List[String]]].toOption.toList.flatMap(
          _.toList.map((pattern, targets) => (dir, join(dir, baseUrl), pattern, targets))
        )
      }

  /** Each package's directory, name, and `exports`/`imports` subpath patterns. */
  private lazy val packages: List[(String, Option[String], Map[String, String])] =
      configs("package.json").map { (dir, json) =>
        def patterns(field: String) =
            json.hcursor.downField(field).as[Map[String, io.circe.Json]].toOption.toList
                .flatMap(_.toList.flatMap((k, v) =>
                    v.asString.orElse(v.hcursor.downField("default").as[String].toOption)
                        .orElse(v.hcursor.downField("import").as[String].toOption)
                        .map(k -> _)
                ))
        dir -> (
          json.hcursor.downField("name").as[String].toOption,
          (patterns("exports") ++
              patterns("imports")).toMap
        )
      }.map { case (dir, (name, ps)) => (dir, name, ps) }

  private def under(dir: String, file: String): Boolean =
      dir.isEmpty || file.replace('\\', '/').startsWith(dir + "/")

  /** `pattern` (one `*` at most) matched against `specifier`: the text the `*` stands for. */
  private def matchPattern(pattern: String, specifier: String): Option[String] =
      pattern.indexOf('*') match
        case -1 => Option.when(pattern == specifier)("")
        case star =>
            val (prefix, suffix) = (pattern.take(star), pattern.drop(star + 1))
            Option.when(
              specifier.startsWith(prefix) && specifier.endsWith(suffix) &&
                  specifier.length >= prefix.length + suffix.length
            )(specifier.substring(prefix.length, specifier.length - suffix.length))

  private def substitute(target: String, captured: String): String =
      target.replace("*", captured)

  /** The project path an aliased specifier names, without the file's extension. */
  def resolve(fromFile: String, specifier: String): Option[String] =
    if specifier.startsWith(".") || specifier.startsWith("/") then return None
    val file = fromFile.replace('\\', '/')
    // the nearest tsconfig/jsconfig with paths that covers the file
    val fromPaths = pathPatterns.filter((dir, _, _, _) => under(dir, file))
        .groupBy(_._1).toList.sortBy(-_._1.length).headOption.toList.flatMap(_._2)
        .flatMap((_, base, pattern, targets) =>
            matchPattern(pattern, specifier).toList.flatMap(captured =>
                targets.map(t => join(base, substitute(t, captured)))
            )
        )
    // the project's own package name and subpath patterns
    val fromPackage = packages.filter((dir, _, _) => under(dir, file)).take(1).flatMap {
        (dir, name, patterns) =>
          val own = name.toList.flatMap { n =>
              if specifier == n || specifier.startsWith(n + "/") then
                val sub = "." + specifier.drop(n.length)
                val viaExports = patterns.toList.flatMap((pattern, target) =>
                    matchPattern(pattern, sub).map(c => join(dir, substitute(target, c)))
                )
                // an Ember app's modules live under `app/`
                viaExports ++ List(join(dir, "app/" + sub.drop(2)), join(dir, sub.drop(2)))
              else Nil
          }
          val hashImports =
              if !specifier.startsWith("#") then Nil
              else
                patterns.toList.flatMap((pattern, target) =>
                    matchPattern(pattern, specifier).map(c => join(dir, substitute(target, c)))
                )
          own ++ hashImports
    }
    // starter conventions, from the nearest package root
    val root = packages.map(_._1).find(dir => under(dir, file)).getOrElse("")
    def at(prefixes: String*)(rest: String) = prefixes.toList.map(p => join(root, p + rest))
    val conventional =
        if specifier.startsWith("~~/") || specifier.startsWith("@@/") then at("")(specifier.drop(3))
        else if specifier.startsWith("@/") then at("src/", "", "app/")(specifier.drop(2))
        else if specifier.startsWith("~/") then at("src/", "app/", "")(specifier.drop(2))
        else if specifier == "$lib" || specifier.startsWith("$lib/") then
          at("src/lib")(specifier.drop(4))
        else Nil
    // a specifier that names the file with its extension keeps it
    (fromPaths ++ fromPackage ++ conventional).iterator
        .flatMap(c =>
            Iterator(c) ++ ScriptExtensions.find(c.endsWith).map(e => c.dropRight(e.length))
        )
        .find(bases.contains)
  end resolve

  /** A relative specifier from `fromFile` to the project path `target`. */
  def relativeSpecifier(fromFile: String, target: String): String =
    val from   = dirOf(fromFile.replace('\\', '/')).split("/").filter(_.nonEmpty).toList
    val to     = target.split("/").filter(_.nonEmpty).toList
    val common = from.zip(to).takeWhile(_ == _).size
    val ups    = from.size - common
    val down   = to.drop(common).mkString("/")
    (if ups == 0 then "./" else "../" * ups) + down
end JsPathAliases
