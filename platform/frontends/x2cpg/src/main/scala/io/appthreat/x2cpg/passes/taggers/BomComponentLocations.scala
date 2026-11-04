package io.appthreat.x2cpg.passes.taggers

import io.circe.Json

import java.nio.file.{Files, InvalidPathException, Path, Paths}

/** A BOM component whose code lies inside the input: `path` is relative to the input root with `/`
  * as separator, `purl` is the component's, `module` its name as its ecosystem spells it.
  */
final case class BomLocatedComponent(path: String, purl: String, module: String)

/** The directories a CycloneDX BOM says its components occupy inside the input (decision 0001, P5:
  * the BOM's component locations mark vendored code external).
  *
  * Which BOM fields name such a location was checked against cdxgen 13.7.0 (source and a real BOM
  * of its `test/data/brotli-exposure/vendored` project), not guessed:
  *   - `cdx:vendored:path` (written with `cdx:vendored=true` by `lib/ecosystems/vendoredCode.js`)
  *     is the repo-relative directory of code copied into the tree, e.g. `third_party/brotli`;
  *   - `cdx:cmake:sourceDir` (`lib/cli/nativeBom.js`) is the directory of a CMake FetchContent or
  *     git submodule dependency. cdxgen's own include attribution reads exactly these two to claim
  *     the files under a component (`lib/ecosystems/cppIncludeResolver.js`,
  *     `createIncludeAttributor`).
  *
  * `evidence.occurrences[].location` is not read: cdxgen writes it where the component is used
  * (evinse's source-code occurrences, `docs/ADVANCED.md`) and for binaries found on a file system,
  * so it names the files that use a dependency, which are the project's own code.
  * `internal:SrcFile` is not read either: it is the manifest a component was read from
  * (`docs/BOM_PIPELINE.md`), such as `package-lock.json`, and the manifest's other components are
  * not that directory's code.
  *
  * A location is used only when it names an existing file or directory inside the input root; one
  * path that two components claim is left out, because the BOM does not say whose code it is.
  */
object BomComponentLocations:

  val PropertyNames: Seq[String] = Seq("cdx:vendored:path", "cdx:cmake:sourceDir")

  /** The located components of the BOMs (`contents` are their JSON texts). */
  def read(contents: Seq[String], root: Path): Seq[BomLocatedComponent] =
    val realRoot = realOrNormal(root)
    val claims = contents.flatMap(io.circe.parser.parse(_).toOption).flatMap { bom =>
      val components = bom.hcursor.downField("components").as[Vector[Json]].getOrElse(Vector.empty)
      flatten(components).flatMap(component => located(component, realRoot))
    }
    claims.distinct.groupBy(_.path).toSeq.sortBy(_._1).flatMap { (_, owners) =>
        // two different components on one path: whose code it is is unknown
        if owners.map(_.purl).distinct.size == 1 then owners.headOption else None
    }

  private def flatten(components: Vector[Json]): Vector[Json] =
      components.flatMap(c =>
          c +: flatten(c.hcursor.downField("components").as[Vector[Json]].getOrElse(Vector.empty))
      )

  private def located(component: Json, root: Path): Seq[BomLocatedComponent] =
    val cursor     = component.hcursor
    val purl       = cursor.downField("purl").as[String].getOrElse("")
    val name       = cursor.downField("name").as[String].getOrElse("")
    val group      = cursor.downField("group").as[String].getOrElse("")
    val properties = cursor.downField("properties").as[Vector[Json]].getOrElse(Vector.empty)
    val paths = properties.flatMap { p =>
      val c = p.hcursor
      Option.when(c.downField("name").as[String].exists(PropertyNames.contains))(
        c.downField("value").as[String].getOrElse("")
      )
    }
    val module = moduleOf(purl, name, group)
    if purl.isEmpty || module.isEmpty then Nil
    else paths.flatMap(insideRoot(_, root)).distinct.map(BomLocatedComponent(_, purl, module))

  /** The path relative to the root, `/`-separated, when `value` names an existing file or directory
    * inside the root other than the root itself.
    */
  def insideRoot(value: String, root: Path): Option[String] =
      if value.trim.isEmpty then None
      else
        try
          val declared = Paths.get(value.trim.replace('\\', '/'))
          val resolved =
              realOrNormal(if declared.isAbsolute then declared else root.resolve(declared))
          Option.when(resolved.startsWith(root) && resolved != root && Files.exists(resolved)) {
              root.relativize(resolved).toString.replace('\\', '/')
          }
        catch case _: InvalidPathException => None

  private def realOrNormal(p: Path): Path =
      try p.toRealPath()
      catch case _: java.io.IOException => p.toAbsolutePath.normalize()

  /** The component's name as its ecosystem spells it: npm `@scope/name`, Maven `group:artifact`,
    * and for the rest the purl's `namespace/name` (`pkg:generic/brotli` -> `brotli`).
    */
  def moduleOf(purl: String, name: String, group: String): String =
    val body = purl.stripPrefix("pkg:")
    val tpe  = body.takeWhile(_ != '/')
    splitNamespace(body.drop(tpe.length + 1)) match
      case (Some(ns), n) if tpe == "maven" => s"$ns:$n"
      case (Some(ns), n)                   => s"$ns/$n"
      case (None, n) if n.nonEmpty         => n
      case _                               => Seq(group, name).filter(_.nonEmpty).mkString("/")

  /** (namespace, name) of a purl's path, without version, qualifiers and subpath, decoded. */
  private def splitNamespace(path: String): (Option[String], String) =
    val noSub = path.takeWhile(c => c != '?' && c != '#')
    // percent-decoding only: a purl's `+` is a plus, not the space a form encodes it as
    val decoded   = java.net.URLDecoder.decode(noSub.replace("+", "%2B"), "UTF-8")
    val versionAt = decoded.lastIndexOf('@')
    val bare      = if versionAt > 0 then decoded.substring(0, versionAt) else decoded
    bare.lastIndexOf('/') match
      case -1 => (None, bare)
      case i  => (Some(bare.substring(0, i)), bare.substring(i + 1))
end BomComponentLocations
