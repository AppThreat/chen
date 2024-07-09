package io.appthreat.javasrc2cpg.passes

import better.files.File
import com.github.javaparser.ast.CompilationUnit
import com.github.javaparser.symbolsolver.JavaSymbolSolver
import com.github.javaparser.symbolsolver.javaparsermodel.JavaParserFacade
import com.github.javaparser.symbolsolver.resolution.typesolvers.{
    JarTypeSolver,
    ReflectionTypeSolver
}
import io.appthreat.javasrc2cpg.JavaSrc2Cpg.JavaSrcEnvVar
import io.appthreat.javasrc2cpg.typesolvers.noncaching.JdkJarTypeSolver
import io.appthreat.javasrc2cpg.typesolvers.{EagerSourceTypeSolver, SimpleCombinedTypeSolver}
import io.appthreat.javasrc2cpg.util.SourceParser
import io.appthreat.javasrc2cpg.{Config, JavaSrc2Cpg, util}
import io.appthreat.x2cpg.datastructures.Global
import io.appthreat.x2cpg.utils.dependency.DependencyResolver
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.ConcurrentWriterCpgPass
import org.slf4j.LoggerFactory

import java.nio.file.{Path, Paths}
import scala.collection.mutable
import scala.util.{Success, Try}

class AstCreationPass(config: Config, cpg: Cpg, sourcesOverride: Option[List[String]] = None)
    extends ConcurrentWriterCpgPass[String](cpg):

  val global: Global = new Global()

  private val sourceFilenames = SourceParser.getSourceFilenames(config, sourcesOverride)

  val (sourceParser, symbolSolver, packagesJarMappings) =
      initParserAndUtils(config, sourceFilenames)

  override def generateParts(): Array[String] = sourceFilenames

  override def runOnPart(diffGraph: DiffGraphBuilder, filename: String): Unit =
    val relativeFilename = Path.of(config.inputPath).relativize(Path.of(filename)).toString
    sourceParser.parseAnalysisFile(relativeFilename) match
      case Some(compilationUnit) =>
          symbolSolver.inject(compilationUnit)
          diffGraph.absorb(
            new AstCreator(
              relativeFilename,
              compilationUnit,
              global,
              symbolSolver,
              packagesJarMappings
            )(
              config.schemaValidation
            ).createAst()
          )

      case None =>

  /** Clear JavaParser caches. Should only be invoked after we no longer need JavaParser, e.g. as
    * soon as we've built the AST layer for all files.
    */
  def clearJavaParserCaches(): Unit =
      JavaParserFacade.clearInstances()

  private def initParserAndUtils(
    config: Config,
    sourceFilenames: Array[String]
  ): (SourceParser, JavaSymbolSolver, mutable.Map[String, mutable.Set[String]]) =
    val dependencies = getDependencyList(config.inputPath)
    val sourceParser = util.SourceParser(config, dependencies.exists(_.contains("lombok")))
    val (symbolSolver, packagesJarMappings) =
        createSymbolSolver(config, dependencies, sourceParser, sourceFilenames)
    (sourceParser, symbolSolver, packagesJarMappings)

  private def getDependencyList(inputPath: String): List[String] =
      if config.fetchDependencies then
        DependencyResolver.getDependencies(Paths.get(inputPath)) match
          case Some(deps) => deps.toList
          case None =>
              List()
      else
        List()

  private def createSymbolSolver(
    config: Config,
    dependencies: List[String],
    sourceParser: SourceParser,
    sourceFilenames: Array[String]
  ): (JavaSymbolSolver, mutable.Map[String, mutable.Set[String]]) =
    val combinedTypeSolver = new SimpleCombinedTypeSolver()
    val symbolSolver       = new JavaSymbolSolver(combinedTypeSolver)

    val jdkPathFromEnvVar = Option(System.getenv(JavaSrcEnvVar.JdkPath.name))
    val jdkPath = (config.jdkPath, jdkPathFromEnvVar) match
      case (None, None) =>
          val javaHome = System.getProperty("java.home")
          if javaHome != null && javaHome.nonEmpty then javaHome
          else System.getenv("JAVA_HOME")
      case (None, Some(jdkPath)) =>
          jdkPath

      case (Some(jdkPath), _) =>
          jdkPath
    var jdkJarTypeSolver: JdkJarTypeSolver = null
    // native-image could have empty JAVA_HOME
    if jdkPath != null && jdkPath.nonEmpty then
      jdkJarTypeSolver = JdkJarTypeSolver.fromJdkPath(jdkPath)
      combinedTypeSolver.addNonCachingTypeSolver(jdkJarTypeSolver)
    val relativeSourceFilenames =
        sourceFilenames.map(filename =>
            Path.of(config.inputPath).relativize(Path.of(filename)).toString
        )

    val sourceTypeSolver =
        EagerSourceTypeSolver(
          relativeSourceFilenames,
          sourceParser,
          combinedTypeSolver,
          symbolSolver
        )
    combinedTypeSolver.addCachingTypeSolver(sourceTypeSolver)
    combinedTypeSolver.addNonCachingTypeSolver(new ReflectionTypeSolver())
    // Add solvers for inference jars
    val jarsList = config.inferenceJarPaths.flatMap(recursiveJarsFromPath).toList
    (jarsList ++ dependencies)
        .flatMap { path =>
            Try(new JarTypeSolver(path)).toOption
        }
        .foreach { combinedTypeSolver.addNonCachingTypeSolver(_) }
    if jdkJarTypeSolver != null then (symbolSolver, jdkJarTypeSolver.packagesJarMappings)
    else (symbolSolver, null)
  end createSymbolSolver

  private def recursiveJarsFromPath(path: String): List[String] =
      Try(File(path)) match
        case Success(file) if file.isDirectory =>
            file.listRecursively
                .map(_.canonicalPath)
                .filter(_.endsWith(".jar"))
                .toList

        case Success(file) if file.canonicalPath.endsWith(".jar") =>
            List(file.canonicalPath)

        case _ =>
            Nil
end AstCreationPass
