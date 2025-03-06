package io.appthreat.jimple2cpg

import better.files.File
import io.appthreat.jimple2cpg.passes.{AstCreationPass, ConfigFileCreationPass, SootAstCreationPass}
import io.appthreat.jimple2cpg.util.Decompiler
import io.appthreat.jimple2cpg.util.ProgramHandlingUtil.{ClassFile, extractClassesInPackageLayout}
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.X2CpgFrontend
import io.appthreat.x2cpg.datastructures.Global
import io.appthreat.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass}
import io.appthreat.x2cpg.utils.FileUtil
import io.appthreat.x2cpg.utils.FileUtil.*
import io.shiftleft.codepropertygraph.Cpg
import soot.options.Options
import soot.{G, Scene}

import java.nio.file.{Files, Path, Paths}
import scala.jdk.CollectionConverters.{EnumerationHasAsScala, SeqHasAsJava}
import scala.language.postfixOps
import scala.util.Try

object Jimple2Cpg:
  val language = "JAVA"

  def apply(): Jimple2Cpg = new Jimple2Cpg()

class Jimple2Cpg extends X2CpgFrontend[Config]:

  import Jimple2Cpg.*

  private def sootLoadApk(input: Path, framework: Option[String] = None): Unit =
    Options.v().set_process_dir(List(input.absolutePathAsString).asJava)
    framework match
      case Some(value) if value.nonEmpty =>
          Options.v().set_src_prec(Options.src_prec_apk)
          Options.v().set_force_android_jar(value)
      case _ =>
          Options.v().set_src_prec(Options.src_prec_apk_c_j)
    Options.v().set_process_multiple_dex(true)
    // workaround for Soot's bug while parsing large apk.
    // see: https://github.com/soot-oss/soot/issues/1256
    Options.v().setPhaseOption("jb", "use-original-names:false")

  /** Load all class files from archives or directories recursively
    *
    * @param src
    *   Source path
    * @param tmpDir
    *   Temp directory
    * @param onlyClasses
    *   Only include .class files
    * @param recurse
    *   Whether to unpack recursively
    * @param depth
    *   Maximum depth of recursion
    * @return
    *   The list of extracted class files whose package path could be extracted, placed on that
    *   package path relative to [[tmpDir]]
    */
  private def loadClassFiles(
    src: Path,
    tmpDir: Path,
    onlyClasses: Boolean,
    recurse: Boolean,
    depth: Int
  ): List[ClassFile] =
      extractClassesInPackageLayout(
        src,
        tmpDir,
        isClass = e => e.extension.contains(".class"),
        isArchive = e => e.isZipFile,
        isConfigFile = e => e.isConfigFile,
        onlyClasses,
        recurse,
        depth
      )

  /** Extract all class files found, place them in their package layout and load them into soot.
    * @param input
    *   The file/directory to traverse for class files.
    * @param tmpDir
    *   The directory to place the class files in their package layout
    * @param scalaSdk
    *   Scala library jar for parsing scala-built jars
    * @param onlyClasses
    *   Include only .class files
    * @param recurse
    *   Whether to unpack recursively
    * @param depth
    *   Maximum depth of recursion
    */
  private def sootLoad(
    input: Path,
    tmpDir: Path,
    scalaSdk: Option[String],
    onlyClasses: Boolean,
    recurse: Boolean,
    depth: Int
  ): List[ClassFile] =
    var sClassPath = tmpDir.absolutePathAsString
    if scalaSdk.nonEmpty then
      sClassPath = sClassPath + java.io.File.pathSeparator + scalaSdk.get
    Options.v().set_soot_classpath(sClassPath)
    Options.v().set_prepend_classpath(true)
    val classFiles               = loadClassFiles(input, tmpDir, onlyClasses, recurse, depth)
    val fullyQualifiedClassNames = classFiles.flatMap(_.fullyQualifiedClassName)
    fullyQualifiedClassNames.foreach { fqcn =>
        if fqcn.contains(".") then
          Scene.v().addBasicClass(fqcn)
          Scene.v().loadClassAndSupport(fqcn)
    }
    classFiles
  end sootLoad

  /** Apply the soot passes
    * @param tmpDir
    *   A temporary directory that will be used as the classpath for extracted class files
    */
  private def cpgApplyPasses(cpg: Cpg, config: Config, tmpDir: Path): Unit =
    val input = Paths.get(config.inputPath)
    configureSoot(config, tmpDir)
    new MetaDataPass(cpg, language, config.inputPath).createAndApply()
    val globalFromAstCreation: () => Global = input.extension match
      case Some(".apk" | ".dex") if Files.isRegularFile(input) =>
          sootLoadApk(input, config.android)
          { () =>
            val astCreator = SootAstCreationPass(cpg, config)
            astCreator.createAndApply()
            astCreator.global
          }
      case _ =>
          val classFiles = sootLoad(
            input,
            tmpDir,
            config.scalaSdk,
            config.onlyClasses,
            config.recurse,
            config.depth
          )
          decompileClassFiles(classFiles, true)

          { () =>
            val astCreator = AstCreationPass(classFiles, cpg, config)
            astCreator.createAndApply()
            astCreator.global
          }
    Scene.v().loadNecessaryClasses()
    val global = globalFromAstCreation()
    TypeNodePass
        .withRegisteredTypes(global.usedTypes.keys().asScala.toList, cpg)
        .createAndApply()
    new ConfigFileCreationPass(cpg).createAndApply()
  end cpgApplyPasses

  private def decompileClassFiles(classFiles: List[ClassFile], decompileJava: Boolean): Unit =
      Option.when(decompileJava) {
          val decompiler     = new Decompiler(classFiles.map(_.file))
          val decompiledJava = decompiler.decompile()

          classFiles.foreach(x =>
            val decompiledJavaSrc = decompiledJava.get(x.fullyQualifiedClassName.get)
            decompiledJavaSrc match
              case Some(src) =>
                  val outputFile = Paths.get(s"${x.file.toString.replace(".class", ".java")}")
                  Files.writeString(outputFile, src)
              case None => // Do Nothing
          )
      }

  override def createCpg(config: Config): Try[Cpg] =
      try
          withNewEmptyCpg(config.outputPath, config: Config) { (cpg, config) =>
              File.temporaryDirectory("jimple2cpg-").apply { tmpDir =>
                  cpgApplyPasses(cpg, config, tmpDir.path)
              }
          }
      finally
          G.reset()

  private def configureSoot(config: Config, outDir: Path): Unit =
    // set application mode
    Options.v().set_app(false)
    Options.v().set_whole_program(false)
    // keep debugging info
    Options.v().set_keep_line_number(true)
    Options.v().set_keep_offset(true)
    // ignore library code
    Options.v().set_no_bodies_for_excluded(true)
    Options.v().set_allow_phantom_refs(true)
    // keep variable names
    Options.v().setPhaseOption("jb.sils", "enabled:false")
    Options.v().setPhaseOption("jb", "use-original-names:true")
    // Keep exceptions
    Options.v().set_show_exception_dests(true)
    Options.v().set_omit_excepting_unit_edges(false)
    // output jimple
    Options.v().set_output_format(Options.output_format_jimple)
    Options.v().set_output_dir(outDir.absolutePathAsString)

    Options.v().set_dynamic_dir(config.dynamicDirs.asJava)
    Options.v().set_dynamic_package(config.dynamicPkgs.asJava)

    if config.fullResolver then
      // full transitive resolution of all references
      Options.v().set_full_resolver(true)
  end configureSoot
end Jimple2Cpg
