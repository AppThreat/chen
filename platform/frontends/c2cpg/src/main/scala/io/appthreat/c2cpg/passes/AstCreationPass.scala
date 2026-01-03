package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.parser.{CdtParser, FileDefaults, HeaderFileFinder}
import io.appthreat.x2cpg.{Ast, SourceFiles}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.NewNode
import io.shiftleft.passes.OrderedParallelCpgPass

import java.io.*
import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import java.util.concurrent.*
import java.util.regex.Pattern
import scala.concurrent.duration.*
import scala.jdk.DurationConverters.*
import scala.util.{Failure, Success, Try, Using}
import scala.util.matching.Regex

object AstCreationPass:
  case class SerializableNode(className: String, properties: java.util.Map[String, Any])
      extends Serializable

  class CpgOOS(out: OutputStream) extends ObjectOutputStream(out):
    enableReplaceObject(true)
    override def replaceObject(obj: Any): Any = obj match
      case n: NewNode =>
          val props = new java.util.HashMap[String, Any]()
          n.properties.foreach { case (k, v) => props.put(k, v) }
          SerializableNode(n.getClass.getName, props)
      case other => other

  class CpgOIS(in: InputStream) extends ObjectInputStream(in):
    enableResolveObject(true)
    override def resolveObject(obj: Any): Any = obj match
      case s: SerializableNode => reconstructNode(s)
      case other               => other

    private def reconstructNode(s: SerializableNode): NewNode =
      val clazz = Class.forName(s.className)
      val node  = clazz.getDeclaredConstructor().newInstance().asInstanceOf[NewNode]
      s.properties.forEach { (k, v) =>
          try
            val camelName = snakeToCamel(k)
            val methods   = clazz.getMethods
            var method    = methods.find(_.getName == camelName)
            if method.isEmpty then
              method = methods.find(_.getName.equalsIgnoreCase(k.replace("_", "")))

            if method.isDefined && method.get.getParameterCount == 1 then
              method.get.invoke(node, v.asInstanceOf[Object])
          catch
            case _: Exception =>
      }
      node

    private def snakeToCamel(s: String): String =
      val tokens = s.split("_")
      if tokens.isEmpty then return s.toLowerCase
      val sb = new StringBuilder(tokens(0).toLowerCase)
      for i <- 1 until tokens.length do
        val t = tokens(i).toLowerCase
        if t.nonEmpty then
          sb.append(t.substring(0, 1).toUpperCase).append(t.substring(1))
      sb.toString
  end CpgOIS
end AstCreationPass

class AstCreationPass(
  cpg: Cpg,
  config: Config,
  timeoutDuration: FiniteDuration = 2.minutes,
  parseTimeoutDuration: FiniteDuration = 2.minutes
) extends OrderedParallelCpgPass[String](cpg):

  import AstCreationPass.*

  private val sharedHeaderFileFinder = new HeaderFileFinder(config.inputPath)
  private val EscapedFileSeparator   = Pattern.quote(java.io.File.separator)
  private val DefaultIgnoredFolders: List[Regex] = List(
    "\\..*".r,
    s"(.*[$EscapedFileSeparator])?tests?[$EscapedFileSeparator].*".r,
    s"(.*[$EscapedFileSeparator])?CMakeFiles[$EscapedFileSeparator].*".r
  )

  if config.enableAstCache then
    Try(Files.createDirectories(Paths.get(config.cacheDir))) match
      case Failure(e) =>
          println(s"Warning: Failed to create cache directory ${config.cacheDir}: ${e.getMessage}")
      case Success(_) =>

  override def generateParts(): Array[String] =
      SourceFiles
          .determine(
            config.inputPath,
            FileDefaults.SOURCE_FILE_EXTENSIONS ++ FileDefaults.HEADER_FILE_EXTENSIONS,
            ignoredDefaultRegex = Option(DefaultIgnoredFolders),
            ignoredFilesRegex = Option(config.ignoredFilesRegex),
            ignoredFilesPath = Option(config.ignoredFiles)
          )
          .sortWith(_.compareToIgnoreCase(_) > 0)
          .toArray

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
    val path                = Paths.get(filename).toAbsolutePath
    val relPath             = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val computationExecutor = Executors.newVirtualThreadPerTaskExecutor()
    val file2OffsetTable    = new ConcurrentHashMap[String, Array[Int]]()
    val fileHash            = if config.enableAstCache then Option(computeEntryHash(path)) else None

    try
      val cachedAst: Option[Ast] = fileHash.flatMap(h => checkAndLoadCache(h, config.cacheDir))
      cachedAst match
        case Some(ast) =>
            Ast.storeInDiffGraph(ast, diffGraph)
        case None =>
            val parser: CdtParser = new CdtParser(config, sharedHeaderFileFinder)
            val parseFuture       = computationExecutor.submit(() => parser.parse(path))
            val parseResult = runWithTimeout(parseFuture, parseTimeoutDuration, computationExecutor)

            parseResult match
              case Some(translationUnit: org.eclipse.cdt.core.dom.ast.IASTTranslationUnit) =>
                  val astFuture = computationExecutor.submit(() =>
                      new AstCreator(relPath, config, translationUnit, file2OffsetTable, fileHash)(
                        using config.schemaValidation
                      ).createAst()
                  )

                  val localDiff = runWithTimeout(astFuture, timeoutDuration, computationExecutor)
                  diffGraph.absorb(localDiff)
              case None =>
      end match
    catch
      case e: TimeoutException =>
          println(s"Timeout occurred during processing for file: $filename: ${e.getMessage}")
      case e: Throwable =>
          println(s"Exception processing file $filename: ${e.getMessage}")
          throw e
    finally
      computationExecutor.shutdown()
      sharedHeaderFileFinder.clear()
      try
        if !computationExecutor.awaitTermination(10, TimeUnit.SECONDS) then
          computationExecutor.shutdownNow()
      catch
        case _: InterruptedException =>
            computationExecutor.shutdownNow()
            Thread.currentThread().interrupt()
    end try
  end runOnPart

  private def computeEntryHash(path: Path): String =
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(path.toAbsolutePath.toString.getBytes("UTF-8"))
    digest.update(Files.readAllBytes(path))
    digest.digest().map("%02x".format(_)).mkString

  private def checkAndLoadCache(hash: String, cacheDir: String): Option[Ast] =
    val cacheFile = Paths.get(cacheDir, s"$hash.ast")
    if !Files.exists(cacheFile) then return None

    Using(new CpgOIS(new FileInputStream(cacheFile.toFile))) { ois =>
        ois.readObject().asInstanceOf[Ast]
    } match
      case Success(ast) =>
          Some(ast)
      case Failure(e) =>
          println(s"Failed to load cache for $hash: ${e.getClass.getSimpleName} - ${e.getMessage}")
          Try(Files.deleteIfExists(cacheFile))
          None

  private def runWithTimeout[T](
    future: Future[T],
    timeout: FiniteDuration,
    executor: ExecutorService
  ): T =
      try
        future.get(timeout.toMinutes, TimeUnit.MINUTES)
      catch
        case _: TimeoutException =>
            future.cancel(true)
            throw new TimeoutException(s"Operation timed out after $timeout")
end AstCreationPass
