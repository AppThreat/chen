package io.appthreat.jssrc2cpg.utils

import better.files.File
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.utils.{Environment, ExternalCommand}
import io.shiftleft.utils.IOUtils
import com.typesafe.config.ConfigFactory
import io.appthreat.jssrc2cpg.Config
import io.appthreat.jssrc2cpg.preprocessing.EjsPreprocessor
import org.slf4j.LoggerFactory
import versionsort.VersionHelper

import java.nio.file.Paths
import scala.util.Failure
import scala.util.Success
import scala.util.matching.Regex
import scala.util.Try

object AstGenRunner:

  private val TypeDefinitionFileExtensions = List(".t.ts", ".d.ts")

  private val IgnoredTestsRegex: Seq[Regex] =
      List(
        ".*cypress\\.json".r,
        ".*test.*\\.json".r
      )

  private val IgnoredFilesRegex: Seq[Regex] = List(
    ".*\\.types\\.js".r,
    ".*\\.devcontainer\\.json".r,
    ".*i18n.*\\.json".r
  )

  case class AstGenRunnerResult(
    parsedFiles: List[(String, String)] = List.empty
  )

  private lazy val astGenCommand = "astgen"
end AstGenRunner

class AstGenRunner(config: Config):

  import AstGenRunner.*

  private val executableArgs = if !config.tsTypes then " --no-tsTypes" else ""

  private def isIgnoredByUserConfig(filePath: String): Boolean =
    lazy val isInIgnoredFiles = config.ignoredFiles.exists {
        case ignorePath if File(ignorePath).isDirectory => filePath.startsWith(ignorePath)
        case ignorePath                                 => filePath == ignorePath
    }
    lazy val isInIgnoredFileRegex = config.ignoredFilesRegex.matches(filePath)
    if isInIgnoredFiles || isInIgnoredFileRegex then
      true
    else
      false

  private def isIgnoredByDefault(filePath: String): Boolean =
    lazy val isIgnored     = IgnoredFilesRegex.exists(_.matches(filePath))
    lazy val isIgnoredTest = IgnoredTestsRegex.exists(_.matches(filePath))
    if isIgnored || isIgnoredTest then
      true
    else
      false

  private def filterFiles(files: List[String], out: File): List[String] =
      files.filter { file =>
          file.stripSuffix(".json").replace(out.pathAsString, config.inputPath) match
            case filePath if TypeDefinitionFileExtensions.exists(filePath.endsWith) => false
            case filePath if isIgnoredByUserConfig(filePath)                        => false
            case _                                                                  => true
      }

  /** Changes the file-extension by renaming this file; if file does not have an extension, it adds
    * the extension. If file does not exist (or is a directory) no change is done and the current
    * file is returned.
    */
  private def changeExtensionTo(file: File, extension: String): File =
    val newName =
        s"${file.nameWithoutExtension(includeAll = false)}.${extension.stripPrefix(".")}"
    if file.isRegularFile then file.renameTo(newName)
    else if file.notExists then File(newName)
    else file

  private def processEjsFiles(in: File, out: File, ejsFiles: List[String]): Try[Seq[String]] =
    val tmpJsFiles = ejsFiles.map { ejsFilePath =>
      val ejsFile           = File(ejsFilePath)
      val sourceFileContent = IOUtils.readEntireFile(ejsFile.path)
      val preprocessContent = new EjsPreprocessor().preprocess(sourceFileContent)
      (out / in.relativize(ejsFile).toString).parent.createDirectoryIfNotExists(createParents =
          true
      )
      val newEjsFile = ejsFile.copyTo(out / in.relativize(ejsFile).toString)
      val jsFile     = changeExtensionTo(newEjsFile, ".js").writeText(preprocessContent)
      newEjsFile.createFile().writeText(sourceFileContent)
      jsFile
    }

    val result =
        ExternalCommand.run(s"$astGenCommand$executableArgs -t ts -o $out", out.toString())

    val jsons = SourceFiles.determine(out.toString(), Set(".json"))
    jsons.foreach { jsonPath =>
      val jsonFile    = File(jsonPath)
      val jsonContent = IOUtils.readEntireFile(jsonFile.path)
      val json        = ujson.read(jsonContent)
      val fileName    = json("fullName").str
      val newFileName = fileName.patch(fileName.lastIndexOf(".js"), ".ejs", 3)
      json("relativeName") = newFileName
      json("fullName") = newFileName
      jsonFile.writeText(json.toString())
    }

    tmpJsFiles.foreach(_.delete())
    result
  end processEjsFiles

  private def ejsFiles(in: File, out: File): Try[Seq[String]] =
    val files = SourceFiles.determine(in.pathAsString, Set(".ejs"))
    if files.nonEmpty then processEjsFiles(in, out, files)
    else Success(Seq.empty)

  private def vueFiles(in: File, out: File): Try[Seq[String]] =
    val files = SourceFiles.determine(in.pathAsString, Set(".vue"))
    if files.nonEmpty then
      ExternalCommand.run(s"$astGenCommand$executableArgs -t vue -o $out", in.toString())
    else Success(Seq.empty)

  private def jsFiles(in: File, out: File): Try[Seq[String]] =
      ExternalCommand.run(s"$astGenCommand$executableArgs -t ts -o $out", in.toString())

  private def runAstGenNative(in: File, out: File): Try[Seq[String]] =
      for
        ejsResult <- ejsFiles(in, out)
        vueResult <- vueFiles(in, out)
        jsResult  <- jsFiles(in, out)
      yield jsResult ++ vueResult ++ ejsResult

  def execute(out: File): AstGenRunnerResult =
    val in = File(config.inputPath)
    runAstGenNative(in, out) match
      case Success(result) =>
          val parsed = filterFiles(SourceFiles.determine(out.toString(), Set(".json")), out)
          AstGenRunnerResult(parsed.map((in.toString(), _)))
      case Failure(_) =>
          AstGenRunnerResult()
end AstGenRunner
