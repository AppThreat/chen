package io.appthreat.x2cpg.testfixtures

import java.net.{JarURLConnection, URL}
import java.nio.file.{Files, Path, Paths}
import java.util.jar.JarFile

import scala.jdk.CollectionConverters.*

/** Materializes classpath resources as real files on disk.
  *
  * sbt 2 serves test resources from its content-addressed virtual-file store, so resource URLs are
  * `jar:file:...!/entry` references into that store instead of paths under `target/`. Tests that
  * walk directories or hand paths to external tools need a real copy; this helper returns the
  * on-disk location directly when the resource already is a plain file (e.g. when running from an
  * IDE), and otherwise extracts the resource into a fresh temp directory - the whole subtree for a
  * directory resource, the single file for a file resource.
  */
object TestResources:

  /** A real directory holding the recursive contents of the classpath directory at `resourcePath`.
    */
  def extractDirectory(resourcePath: String)(using owner: Class[?]): Path =
      resolve(resourcePath)

  /** A real file for the classpath file at `resourcePath`. */
  def extractFile(resourcePath: String)(using owner: Class[?]): Path =
      resolve(resourcePath)

  private def resolve(resourcePath: String)(using owner: Class[?]): Path =
    val normalized = resourcePath.stripPrefix("/")
    val url: URL = Option(owner.getClassLoader.getResource(normalized))
        .getOrElse(sys.error(s"classpath resource not found: $resourcePath"))
    if url.getProtocol == "file" then Paths.get(url.toURI)
    else extractFromJar(url, normalized)

  /** Handles `jar:` URLs: real jars as well as sbt 2's content-addressed store, whose entries are
    * addressed the same way.
    */
  private def extractFromJar(url: URL, normalized: String): Path =
    val connection = url.openConnection match
      case jar: JarURLConnection => jar
      case other                 => sys.error(s"unsupported resource URL: $url")
    usingResource(connection.getJarFile) { jar =>
      val dirPrefix = normalized.stripSuffix("/") + "/"
      val children = jar.entries().asScala.toSeq
          .filter(entry => entry.getName.startsWith(dirPrefix) && !entry.isDirectory)
      val out = Files.createTempDirectory("chen-test-resources-")
      if children.nonEmpty then
        children.foreach(copy(jar, out, dirPrefix))
        out
      else
        Option(jar.getEntry(normalized)) match
          case Some(entry) =>
              copy(jar, out, "")(entry)
              out.resolve(entry.getName.stripPrefix(dirPrefix))
          case None => sys.error(s"no jar entry for $normalized in $url")
    }

  private def copy(
    jar: JarFile,
    out: Path,
    dirPrefix: String
  )(entry: java.util.zip.ZipEntry): Unit =
    val dest = out.resolve(entry.getName.stripPrefix(dirPrefix))
    Files.createDirectories(dest.getParent)
    usingResource(jar.getInputStream(entry)) { in =>
        usingResource(Files.newOutputStream(dest)) { outStream =>
            in.transferTo(outStream)
        }
    }

  private def usingResource[A <: AutoCloseable, B](resource: A)(f: A => B): B =
      try f(resource)
      finally resource.close()
end TestResources
