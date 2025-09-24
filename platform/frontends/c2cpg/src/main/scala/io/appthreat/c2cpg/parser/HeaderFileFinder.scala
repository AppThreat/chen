package io.appthreat.c2cpg.parser

import better.files.*
import io.appthreat.x2cpg.SourceFiles
import org.jline.utils.Levenshtein

import java.nio.file.Path

class HeaderFileFinder(root: String):

  private val nameToPathMap: Map[String, List[Path]] = SourceFiles
      .determine(root, FileDefaults.HEADER_FILE_EXTENSIONS)
      .map { p =>
        val file = File(p)
        (file.name, file.path)
      }
      .groupBy(_._1)
      .view
      .mapValues(_.map(_._2))
      .toMap

  /** Given an unresolved header file, given as a non-existing absolute path, determine whether a
    * header file with the same name can be found anywhere in the code base. Uses the name of the
    * unresolved path to find candidates and then finds the candidate path with the minimum
    * Levenshtein distance to the unresolved path.
    */
  def find(path: String): Option[String] =
    val requestedFileName = File(path).name
    val candidates        = nameToPathMap.getOrElse(requestedFileName, List.empty)

    if candidates.isEmpty then
      None
    else
      val (minDistancePath, _) = candidates.foldLeft((Option.empty[Path], Int.MaxValue)) {
          case ((minPath, minDist), candidatePath) =>
              val distance = Levenshtein.distance(candidatePath.toString, path)
              if distance < minDist then
                (Some(candidatePath), distance)
              else
                (minPath, minDist)
      }
      minDistancePath.map(_.toString)
end HeaderFileFinder
