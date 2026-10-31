package io.appthreat.javasrc2cpg

import better.files.File
import io.appthreat.javasrc2cpg.passes.{
    AstCreationPass,
    ConfigFileCreationPass,
    JavaTypeHintCallLinker,
    JavaTypeRecoveryPass,
    ReflectionLoweringPass,
    TypeInferencePass
}
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.passes.frontend.{
    MetaDataPass,
    TypeNodePass,
    XTypeRecovery,
    XTypeRecoveryConfig
}
import io.appthreat.x2cpg.X2CpgFrontend
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.NewConfigFile
import overflowdb.BatchedUpdate
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.passes.CpgPassBase

import scala.jdk.CollectionConverters.*
import scala.util.Try
import scala.util.matching.Regex

class JavaSrc2Cpg extends X2CpgFrontend[Config]:
  import JavaSrc2Cpg.*

  override def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config: Config) { (cpg, config) =>
        new MetaDataPass(cpg, language, config.inputPath).createAndApply()
        val astCreationPass = new AstCreationPass(config, cpg)
        astCreationPass.createAndApply()
        astCreationPass.clearJavaParserCaches()
        new ConfigFileCreationPass(cpg).createAndApply()
        storeDependencyClasspath(config, cpg, astCreationPass)
        if !config.skipTypeInfPass then
          TypeNodePass.withRegisteredTypes(
            astCreationPass.global.usedTypes.keys().asScala.toList,
            cpg
          ).createAndApply()
          // Two rounds: a link whose base this pass itself resolves in the first one (`cart
          // .getSecurity().login()`, the getter Lombok-generated) only then carries the type the
          // next link's match needs (chen#245). The parts of the second round are the calls still
          // carrying an unresolved signature, so a graph the first round settled costs a filter.
          new TypeInferencePass(cpg).createAndApply()
          new TypeInferencePass(cpg).createAndApply()
        // After type inference, so the reflective call sites it rewrites carry their final
        // methodFullNames, and before the overlays, so the call linkers see ordinary calls.
        new ReflectionLoweringPass(cpg).createAndApply()
        if config.enableTypeRecovery then
          // The call site atom passes `enableTypeRecovery = true`; until now nothing read the
          // flag, so Java type recovery never ran (chen#245). Measured on the callsites Java
          // subset before it was kept.
          typeRecoveryPasses(cpg, Some(config)).foreach(_.createAndApply())
      }
end JavaSrc2Cpg

object JavaSrc2Cpg:
  val language: String = Languages.JAVASRC

  /** The resolved dependency classpath as a config file of the atom: the slice reads it to map a
    * class to the Maven artifact of the jar that carries it. Empty when no dependencies were
    * resolved, so a project built without them carries no mapping.
    */
  private def storeDependencyClasspath(
    config: Config,
    cpg: Cpg,
    astCreationPass: AstCreationPass
  ): Unit =
    val jars = astCreationPass.dependencyJarPaths
    if jars.nonEmpty then
      val diff = new BatchedUpdate.DiffGraphBuilder
      diff.addNode(
        NewConfigFile()
            .name(DependencyClasspathFileName)
            .content(ujson.write(ujson.Arr.from(jars.map(jar => ujson.Str(jar)))))
      )
      BatchedUpdate.applyDiff(cpg.graph, diff)

  val DependencyClasspathFileName = "java-classpath.json"

  val sourceFileExtensions: Set[String] = Set(".java")

  val DefaultIgnoredFilesRegex: List[Regex] = List(".git", ".mvn", "test").flatMap { directory =>
      List(s"(^|\\\\)$directory($$|\\\\)".r.unanchored, s"(^|/)$directory($$|/)".r.unanchored)
  }

  val DefaultConfig: Config =
      Config().withDefaultIgnoredFilesRegex(DefaultIgnoredFilesRegex)

  def apply(): JavaSrc2Cpg = new JavaSrc2Cpg()

  def typeRecoveryPasses(cpg: Cpg, config: Option[Config] = None): List[CpgPassBase] =
      List(
        // `configFor` also carries `typePropagationIterations`, which this call site used to
        // drop on the floor - Java always ran the default iteration count.
        new JavaTypeRecoveryPass(
          cpg,
          config.map(XTypeRecovery.configFor).getOrElse(XTypeRecoveryConfig())
        ),
        new JavaTypeHintCallLinker(cpg)
      )

  def showEnv(): Unit =
    val value =
        JavaSrcEnvVar.values.foreach { envVar =>
          val currentValue = Option(System.getenv(envVar.name)).getOrElse("<unset>")
          println(s"${envVar.name}:")
          println(s"  Description  : ${envVar.description}")
          println(s"  Current value: $currentValue")
        }

  enum JavaSrcEnvVar(val name: String, val description: String):
    case JdkPath
        extends JavaSrcEnvVar(
          "JAVASRC_JDK_PATH",
          "Path to the JDK home used for retrieving type information about builtin Java types."
        )
end JavaSrc2Cpg
