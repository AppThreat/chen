package io.appthreat.javasrc2cpg.util

import io.appthreat.x2cpg.utils.SourceDecoding

import java.nio.charset.Charset
import java.nio.file.{Files, Path}
import java.util.concurrent.ConcurrentHashMap
import scala.util.Try

/** The charset a Java build compiles a source file with: javac takes it from `-encoding`, which the
  * build sets - Maven's `project.build.sourceEncoding` or the compiler plugin's `<encoding>`,
  * Gradle's `options.encoding`, Ant's `<javac encoding>`. The nearest build file above the file
  * that sets one decides; none, and the file is read as [[SourceDecoding]] reads any.
  */
class SourceEncoding(root: Path):

  private val top         = root.toAbsolutePath.normalize
  private val byDirectory = new ConcurrentHashMap[Path, Option[Charset]]()

  def forFile(file: Path): Option[Charset] =
      Option(file.toAbsolutePath.normalize.getParent).flatMap(forDirectory)

  // not computeIfAbsent: the parent's lookup would update the map from inside its own update
  private def forDirectory(dir: Path): Option[Charset] =
      Option(byDirectory.get(dir)).getOrElse {
          val found = declaredIn(dir).orElse(
            Option(dir.getParent).filter(_.startsWith(top)).flatMap(forDirectory)
          )
          byDirectory.putIfAbsent(dir, found)
          found
      }

  private def declaredIn(dir: Path): Option[Charset] =
      SourceEncoding.BuildFiles.iterator
          .map(dir.resolve)
          .filter(Files.isRegularFile(_))
          .flatMap(f => Try(Files.readString(f, Charset.forName("ISO-8859-1"))).toOption)
          .flatMap(SourceEncoding.declaredBy)
          .nextOption()
end SourceEncoding

object SourceEncoding:

  val BuildFiles: Seq[String] = Seq("pom.xml", "build.gradle", "build.gradle.kts", "build.xml")

  private val Patterns = Seq(
    "<project\\.build\\.sourceEncoding>\\s*([^<\\s]+)\\s*</".r,
    "<encoding>\\s*([^<\\s]+)\\s*</encoding>".r,
    "options\\.encoding\\s*=\\s*['\"]([^'\"]+)['\"]".r,
    "<javac\\b[^>]*\\sencoding\\s*=\\s*\"([^\"]+)\"".r
  )

  /** The charset a build file's text sets for its Java sources. A property reference
    * (`${encoding}`) is not resolved.
    */
  def declaredBy(buildFile: String): Option[Charset] =
      Patterns.iterator
          .flatMap(_.findFirstMatchIn(buildFile))
          .map(_.group(1))
          .filterNot(_.contains("$"))
          .flatMap(SourceDecoding.charsetNamed)
          .nextOption()
end SourceEncoding
