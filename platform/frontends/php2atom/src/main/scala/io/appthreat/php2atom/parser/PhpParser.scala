package io.appthreat.php2atom.parser

import better.files.File
import io.appthreat.php2atom.Config
import io.appthreat.php2atom.parser.Domain.PhpFile
import io.appthreat.x2cpg.utils.ExternalCommand
import org.slf4j.LoggerFactory

import java.nio.file.Paths
import scala.util.{Failure, Success, Try}

class PhpParser private (phpParserPath: String, phpIniPath: String):

    private val logger = LoggerFactory.getLogger(this.getClass)

    private def phpParseCommand(filename: String): String =
        val phpParserCommands = "--with-recovery --resolve-names -P --json-dump"
        phpParserPath match
            case "phpastgen" =>
                s"$phpParserPath $phpParserCommands $filename"
            case _ =>
                s"php --php-ini $phpIniPath $phpParserPath $phpParserCommands $filename"

    def parseFile(inputPath: String, phpIniOverride: Option[String]): Option[PhpFile] =
        val inputFile      = File(inputPath)
        val inputFilePath  = inputFile.canonicalPath
        val inputDirectory = inputFile.parent.canonicalPath

        val command = phpParseCommand(inputFilePath)

        ExternalCommand.run(command, inputDirectory, true) match
            case Success(output) =>
                processParserOutput(output, inputFilePath)

            case Failure(exception) =>
                logger.debug(s"Failure running php-parser with $command", exception.getMessage)
                None

    private def processParserOutput(output: Seq[String], filename: String): Option[PhpFile] =
        val maybeJson =
            linesToJsonValue(output, filename)
        maybeJson.flatMap(jsonValueToPhpFile(_, filename))

    private def linesToJsonValue(lines: Seq[String], filename: String): Option[ujson.Value] =
        if lines.exists(_.startsWith("[")) then
            val jsonString = lines.dropWhile(_.charAt(0) != '[').mkString("\n")
            Try(Option(ujson.read(jsonString))) match
                case Success(Some(value)) => Some(value)

                case Success(None) =>
                    logger.debug(s"Parsing json string for $filename resulted in null return value")
                    None

                case Failure(exception) =>
                    logger.debug(
                      s"Parsing json string for $filename failed with exception",
                      exception
                    )
                    None
        else
            logger.debug(s"No JSON output for $filename")
            None

    private def jsonValueToPhpFile(json: ujson.Value, filename: String): Option[PhpFile] =
        Try(Domain.fromJson(json)) match
            case Success(phpFile) => Some(phpFile)

            case Failure(e) =>
                logger.debug(s"Failed to generate intermediate AST for $filename", e)
                None
end PhpParser

object PhpParser:
    private val logger = LoggerFactory.getLogger(this.getClass())

    val PhpParserBinEnvVar = "PHP_PARSER_BIN"

    private def defaultPhpIni: String =
        val tmpIni = File.newTemporaryFile(suffix = "-php.ini").deleteOnExit()
        tmpIni.writeText("memory_limit = -1")
        tmpIni.canonicalPath

    private def isPhpAstgenSupported: Boolean =
        val result = ExternalCommand.run("phpastgen --help", ".")
        result match
            case Success(listString) =>
                true
            case Failure(exception) =>
                false

    private def defaultPhpParserBin: String =
        val dir =
            Paths.get(
              this.getClass.getProtectionDomain.getCodeSource.getLocation.toURI
            ).toAbsolutePath.toString

        val fixedDir = new java.io.File(dir.substring(0, dir.indexOf("php2atom"))).toString

        val builtInGen = Paths.get(
          fixedDir,
          "php2atom",
          "vendor",
          "bin",
          "php-parse"
        ).toAbsolutePath.toString
        if File(builtInGen).exists() then builtInGen
        else "phpastgen"

    private def configOverrideOrDefaultPath(
      identifier: String,
      maybeOverride: Option[String],
      defaultValue: => String
    ): Option[String] =
        val pathString = maybeOverride match
            case Some(overridePath) if overridePath.nonEmpty =>
                overridePath
            case _ =>
                defaultValue

        File(pathString) match
            case file if file.exists() && file.isRegularFile(File.LinkOptions.follow) =>
                Some(file.canonicalPath)
            case _ => Some(defaultValue)

    private def maybePhpParserPath(config: Config): Option[String] =
        val phpParserPathOverride =
            config.phpParserBin
                .orElse(Option(System.getenv(PhpParserBinEnvVar)))

        configOverrideOrDefaultPath("PhpParserBin", phpParserPathOverride, defaultPhpParserBin)

    private def maybePhpIniPath(config: Config): Option[String] =
        configOverrideOrDefaultPath("PhpIni", config.phpIni, defaultPhpIni)

    def getParser(config: Config): Option[PhpParser] =
        for (
          phpParserPath <- maybePhpParserPath(config);
          phpIniPath    <- maybePhpIniPath(config)
        )
            yield new PhpParser(phpParserPath, phpIniPath)
end PhpParser
