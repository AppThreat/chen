package io.appthreat.jssrc2cpg.parser

import io.shiftleft.utils.IOUtils
import ujson.Value.Value
import java.nio.file.{Path, Paths}
import scala.util.Try

object BabelJsonParser:

  case class ParseResult(
    filename: String,
    fullPath: String,
    json: Value,
    fileContent: String,
    typeMap: Map[Int, String]
  )

  def readFile(rootPath: Path, file: Path): ParseResult =
    val typeMapPath = Paths.get(file.toString.replace(".json", ".typemap"))
    val typeMap = if typeMapPath.toFile.exists() then
      Try {
          val typeMapJsonContent = IOUtils.readEntireFile(typeMapPath)
          val typeMapJson        = ujson.read(typeMapJsonContent)
          typeMapJson.obj.map { case (k, v) => k.toInt -> v.str }.toMap
      }.getOrElse(Map.empty)
    else
      Map.empty[Int, String]

    val jsonContent = IOUtils.readEntireFile(file)
    val json        = ujson.read(jsonContent)
    val relative    = json("relativeName").str
    val fullPath    = Paths.get(rootPath.toString, relative)
    // the project-relative name is the same on every OS: framework conventions (`app/routes/`,
    // `pages/api/`) and provenance (`via:<file>#<line>`) are written with `/`
    val filename = relative.replace('\\', '/')
    // a file astgen rewrote before parsing (an Ember template) comes with the text its offsets index
    val content =
        json.obj.get("source").flatMap(_.strOpt).getOrElse(sourceAsAstgenReadsIt(fullPath))
    ParseResult(filename, fullPath.toString, json, content, typeMap)
  end readFile

  /** astgen's offsets index the file as Node's `readFileSync(file, "utf-8")` returns it: a UTF-8
    * byte-order mark stays, as its first character, and malformed bytes become U+FFFD.
    */
  def sourceAsAstgenReadsIt(path: Path): String =
      new String(java.nio.file.Files.readAllBytes(path), java.nio.charset.StandardCharsets.UTF_8)

end BabelJsonParser
