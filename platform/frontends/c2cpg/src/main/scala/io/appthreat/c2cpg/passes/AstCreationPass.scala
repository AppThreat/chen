package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.parser.{CdtParser, FileDefaults, HeaderFileFinder}
import io.appthreat.x2cpg.{Ast, AstEdge, SourceFiles, ValidationMode}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.NewNode
import io.shiftleft.passes.StreamingCpgPass
import upickle.default.*

import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import java.util.concurrent.*
import java.util.regex.Pattern
import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try}
import scala.util.matching.Regex

object AstCreationPass:
  private val theoriticalMaxProcs  = Math.max(1, Runtime.getRuntime.availableProcessors() / 3)
  private val maxConcurrentParsers = Math.min(4, theoriticalMaxProcs)
  private val astCreationSemaphore = new Semaphore(maxConcurrentParsers)
  private val parseExecutor        = Executors.newCachedThreadPool()

  case class CachedNode(className: String, properties: Map[String, ujson.Value])
      derives ReadWriter

  case class CachedEdge(srcId: Int, dstId: Int, label: String)
      derives ReadWriter

  case class CachedAst(
    rootIdx: Option[Int],
    nodes: List[CachedNode],
    edges: List[CachedEdge]
  ) derives ReadWriter

  object Serialization:

    def toCached(ast: Ast): CachedAst =
      val allNodes    = ast.nodes.distinct.toVector
      val nodeToIndex = allNodes.zipWithIndex.toMap

      val cachedNodes = allNodes.map { n =>
        val propsMap = n.properties match
          case m: java.util.Map[?, ?]        => m.asScala
          case m: scala.collection.Map[?, ?] => m
          case null                          => Map.empty

        val safeProps = propsMap.map {
            case (k: String, v) => k          -> toUjson(v)
            case (k, v)         => k.toString -> toUjson(v)
        }.toMap

        CachedNode(n.getClass.getName, safeProps)
      }.toList

      def serializeEdgeList(edges: scala.collection.Seq[AstEdge], label: String): List[CachedEdge] =
          edges.collect {
              case e if nodeToIndex.contains(e.src) && nodeToIndex.contains(e.dst) =>
                  CachedEdge(nodeToIndex(e.src), nodeToIndex(e.dst), label)
          }.toList

      val allEdges =
          serializeEdgeList(ast.edges, "AST") ++
              serializeEdgeList(ast.refEdges, "REF") ++
              serializeEdgeList(ast.bindsEdges, "BINDS") ++
              serializeEdgeList(ast.receiverEdges, "RECEIVER") ++
              serializeEdgeList(ast.argEdges, "ARGUMENT") ++
              serializeEdgeList(ast.conditionEdges, "CONDITION") ++
              serializeEdgeList(ast.captureEdges, "CAPTURE")

      val rootIdx = ast.root.flatMap(nodeToIndex.get)

      CachedAst(rootIdx, cachedNodes, allEdges)
    end toCached

    def fromCached(cAst: CachedAst)(implicit validation: ValidationMode): Ast =
      val nodesVector = cAst.nodes.map(reconstructNode).toVector

      def getEdges(label: String): Seq[AstEdge] =
          cAst.edges.collect {
              case ce if ce.label == label =>
                  AstEdge(nodesVector(ce.srcId), nodesVector(ce.dstId))
          }

      Ast(
        nodesVector,
        getEdges("AST"),
        getEdges("CONDITION"),
        getEdges("REF"),
        getEdges("BINDS"),
        getEdges("RECEIVER"),
        getEdges("ARGUMENT"),
        getEdges("CAPTURE")
      )

    private def toUjson(v: Any): ujson.Value = v match
      case s: String       => ujson.Str(s)
      case b: Boolean      => ujson.Bool(b)
      case i: Int          => ujson.Num(i)
      case l: Long         => ujson.Num(l.toDouble)
      case d: Double       => ujson.Num(d)
      case xs: Iterable[?] => ujson.Arr.from(xs.map(toUjson))
      case xs: Array[?]    => ujson.Arr.from(xs.map(toUjson))
      case other           => ujson.Str(other.toString)

    private def fromUjson(v: ujson.Value): Any = v match
      case ujson.Str(s)  => s
      case ujson.Bool(b) => b
      case ujson.Num(n) =>
          if n.isValidInt then n.toInt
          else if n.toLong.toDouble == n then n.toLong
          else n
      case ujson.Arr(arr) => arr.map(fromUjson).toList
      case _              => v.toString

    private def reconstructNode(cn: CachedNode): NewNode =
      if !cn.className.startsWith("io.shiftleft.codepropertygraph.generated.nodes.") then
        throw new SecurityException(s"Illegal class in cache: ${cn.className}")

      val clazz = Class.forName(cn.className)
      val node  = clazz.getDeclaredConstructor().newInstance().asInstanceOf[NewNode]

      cn.properties.foreach { case (k, v) =>
          try
            val camelName = snakeToCamel(k)
            val methods   = clazz.getMethods
            var method    = methods.find(_.getName == camelName)
            if method.isEmpty then
              method = methods.find(_.getName.equalsIgnoreCase(k.replace("_", "")))

            if method.isDefined && method.get.getParameterCount == 1 then
              val arg = fromUjson(v)
              method.get.invoke(node, arg.asInstanceOf[Object])
          catch
            case _: Exception =>
      }
      node
    end reconstructNode

    private def snakeToCamel(s: String): String =
      val tokens = s.split("_")
      if tokens.isEmpty then return s.toLowerCase
      val sb = new StringBuilder(tokens(0).toLowerCase)
      for i <- 1 until tokens.length do
        val t = tokens(i).toLowerCase
        if t.nonEmpty then
          sb.append(t.substring(0, 1).toUpperCase).append(t.substring(1))
      sb.toString
  end Serialization
end AstCreationPass

class AstCreationPass(
  cpg: Cpg,
  config: Config,
  timeoutDuration: FiniteDuration = 2.minutes,
  parseTimeoutDuration: FiniteDuration = 2.minutes
) extends StreamingCpgPass[String](cpg):

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
    val path             = Paths.get(filename).toAbsolutePath
    val relPath          = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val file2OffsetTable = new ConcurrentHashMap[String, Array[Int]]()
    val fileHash         = if config.enableAstCache then Option(computeEntryHash(path)) else None

    AstCreationPass.astCreationSemaphore.acquire()
    try
      val cachedAst: Option[Ast] = fileHash.flatMap(h => checkAndLoadCache(h, config.cacheDir))
      cachedAst match
        case Some(ast) =>
            if !config.onlyAstCache then Ast.storeInDiffGraph(ast, diffGraph)
        case None =>
            val parser: CdtParser = new CdtParser(config, sharedHeaderFileFinder)
            val parseResult       = runWithTimeout(() => parser.parse(path), parseTimeoutDuration)
            parseResult match
              case Some(translationUnit: org.eclipse.cdt.core.dom.ast.IASTTranslationUnit) =>
                  val localDiff = runWithTimeout(
                    () =>
                        new AstCreator(
                          relPath,
                          config,
                          translationUnit,
                          file2OffsetTable,
                          fileHash
                        )(
                          using config.schemaValidation
                        ).createAst(),
                    timeoutDuration
                  )
                  if !config.onlyAstCache then diffGraph.absorb(localDiff)
              case None =>
      end match
    catch
      case e: TimeoutException =>
          println(s"Timeout occurred during processing for file: $path: ${e.getMessage}")
      case e: ExecutionException =>
          val cause = e.getCause
          println(
            s"Exception processing file $path: ${cause.getClass.getSimpleName} - ${cause.getMessage}"
          )
//          cause.printStackTrace()
      case e: Throwable =>
          println(s"Exception processing file $path: ${e.getClass.getSimpleName} - ${e.getMessage}")
//          e.printStackTrace()
    finally
      AstCreationPass.astCreationSemaphore.release()
      sharedHeaderFileFinder.clear()
    end try
  end runOnPart

  private def computeEntryHash(path: Path): String =
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(path.toAbsolutePath.toString.getBytes("UTF-8"))
    digest.update(Files.readAllBytes(path))
    digest.digest().map("%02x".format(_)).mkString

  private def checkAndLoadCache(hash: String, cacheDir: String): Option[Ast] =
    val cacheFile = Paths.get(cacheDir, s"$hash.json")
    if !Files.exists(cacheFile) then return None

    try
      val bytes                            = Files.readAllBytes(cacheFile)
      val cachedAst                        = readBinary[CachedAst](bytes)
      implicit val valMode: ValidationMode = config.schemaValidation
      Some(Serialization.fromCached(cachedAst))
    catch
      case e: Exception =>
          println(s"Failed to load cache for $hash: ${e.getClass.getSimpleName} - ${e.getMessage}")
          Try(Files.deleteIfExists(cacheFile))
          None

  private def runWithTimeout[T](block: () => T, timeout: FiniteDuration): T =
    val future = AstCreationPass.parseExecutor.submit(new Callable[T]:
      override def call(): T = block()
    )
    try
      future.get(timeout.toMinutes, TimeUnit.MINUTES)
    catch
      case _: TimeoutException =>
          future.cancel(true)
          throw new TimeoutException(s"Operation timed out after $timeout")
      case e: InterruptedException =>
          future.cancel(true)
          val cause = e.getCause
          cause.printStackTrace()
          throw new InterruptedException(s"Operation interrupted - ${cause.getMessage}")
end AstCreationPass
