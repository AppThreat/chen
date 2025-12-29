package io.appthreat.c2cpg.parser

import better.files.*
import io.appthreat.x2cpg.SourceFiles

import java.nio.file.{Files, Path, Paths}
import java.util.concurrent.ConcurrentHashMap
import scala.jdk.CollectionConverters.*

class HeaderFileFinder(root: String):

  private val findCache = new ConcurrentHashMap[(String, Option[String]), Option[String]]()
  private val nameToPathMap: Map[String, List[(Path, Seq[String])]] = SourceFiles
      .determine(root, FileDefaults.HEADER_FILE_EXTENSIONS)
      .map { p =>
        val file     = File(p)
        val segments = file.path.iterator().asScala.toSeq.reverse.map(_.toString)
        (file.name, (file.path, segments))
      }
      .groupBy(_._1)
      .view
      .mapValues(_.map(_._2))
      .toMap

  /** Given an unresolved header path (e.g., "common/util.h" or just "util.h"), find the best
    * matching file in the project.
    * @param path
    *   The include string (e.g., "compiler.h")
    * @param currentSourceFile
    *   The file currently being parsed (used for proximity scoring)
    */
  def find(path: String, currentSourceFile: Option[Path]): Option[String] =
    if Files.exists(Paths.get(path)) then
      return Option(path)

    val sourceDir = currentSourceFile.map(_.getParent.toString)
    findCache.computeIfAbsent((path, sourceDir), _ => calculateMatch(path, currentSourceFile))

  private def calculateMatch(path: String, currentSourceFile: Option[Path]): Option[String] =
    val requestedFile = File(path)
    val requestedName = requestedFile.name
    val candidates    = nameToPathMap.getOrElse(requestedName, List.empty)

    candidates match
      case Nil =>
          None
      case (singlePath, _) :: Nil =>
          Option(singlePath.toString)
      case multiple =>
          val requestedSegments =
              requestedFile.path.iterator().asScala.toSeq.reverse.map(_.toString)

          val sourceSegments =
              currentSourceFile.map(_.iterator().asScala.toSeq).getOrElse(Seq.empty)
          val (bestMatchPath, _) = multiple.maxBy { case (candidatePath, candidateSegments) =>
              val suffixScore = requestedSegments.zip(candidateSegments)
                  .takeWhile { case (r, c) => r == c }.length
              val proximityScore = if suffixScore > 0 && sourceSegments.nonEmpty then
                val candPathSegments = candidatePath.iterator().asScala.toSeq
                sourceSegments.zip(candPathSegments)
                    .takeWhile { case (s, c) => s == c }.length
              else
                0

              (suffixScore, proximityScore)
          }

          Option(bestMatchPath.toString)
    end match
  end calculateMatch

end HeaderFileFinder
