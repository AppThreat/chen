package io.appthreat.c2cpg

import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.passes.{
    AstCreationPass,
    ConfigFileCreationPass,
    ConstantTagPass,
    DeclarationAttributesPass,
    PreprocessorPass,
    ReferenceKindPass,
    TypeDeclNodePass
}
import io.appthreat.c2cpg.utils.IncludeAutoDiscovery
import io.appthreat.x2cpg.X2Cpg.withNewEmptyCpg
import io.appthreat.x2cpg.X2CpgFrontend
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.resolveCacheDir
import io.appthreat.x2cpg.passes.frontend.{AstCacheStore, CacheControl, MetaDataPass, TypeNodePass}
import io.appthreat.x2cpg.passes.linking.FragmentSplicePass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages

import io.appthreat.c2cpg.parser.{MacroCensus, ProjectSources}

import java.nio.file.{Files, Paths}
import scala.util.Try

class C2Cpg extends X2CpgFrontend[Config]:

  def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config) { (cpg, config) =>
        CGlobal.reset()
        new MetaDataPass(cpg, Languages.NEWC, config.inputPath).createAndApply()
        val updatedConfig = if config.includePathsAutoDiscovery then
          val projectIncludes =
              IncludeAutoDiscovery.discoverProjectIncludePaths(Paths.get(config.inputPath))
          if projectIncludes.nonEmpty then
            println(s"Auto-discovered ${projectIncludes.size} project include paths")
          config.withIncludePaths(config.includePaths ++ projectIncludes.map(_.toString))
        else
          config
        val censusConfig = C2Cpg.withCensusDefines(updatedConfig)
        val sources      = new ProjectSources(censusConfig)
        sources.database.foreach(db =>
            println(
              s"Using the compilation database ${db.path} (${db.files.size} translation units)"
            )
        )

        if !warmRestoreFromFragments(cpg, censusConfig, sources) then
          new AstCreationPass(cpg, censusConfig, projectSources = sources).createAndApply()

        if !config.onlyAstCache then
          new ConfigFileCreationPass(cpg).createAndApply()
          TypeNodePass.withRegisteredTypes(CGlobal.typesSeen(), cpg).createAndApply()
          new TypeDeclNodePass(cpg, CGlobal.lastMembers)(using config.schemaValidation)
              .createAndApply()
          new ConstantTagPass(cpg, CGlobal.lastConstants).createAndApply()
          new ReferenceKindPass(cpg, CGlobal.lastArrayTypedefs).createAndApply()
          new DeclarationAttributesPass(cpg).createAndApply()
      }

  /** Fastest-splice warm restore: when fragment caching is enabled (atom `--flux`) and every source
    * file is already cached as a `.frag`, reconstruct the AST layer by splicing the cached
    * mini-graphs straight into the graph - skipping parsing AND the diff-graph rebuild - instead of
    * running the parallel [[AstCreationPass]]. Returns false (so the normal pass runs) when caching
    * is off, in cache-warming mode, or the project is not fully cached.
    */
  private def warmRestoreFromFragments(cpg: Cpg, config: Config, sources: ProjectSources): Boolean =
      if !config.enableAstCache || config.onlyAstCache || !CacheControl.useFragments then false
      else
        val files = sources.files
        if files.isEmpty then false
        else
          val store = new AstCacheStore(
            config.enableAstCache,
            resolveCacheDir(config.inputPath, config.cacheDir),
            config.onlyAstCache
          )
          val fragments =
              files.toSeq.map(f =>
                  store.fragmentFor(
                    AstCreationPass.fileCacheKey(f),
                    AstCreationPass.fileFingerprint(config, sources, f)
                  )
              )
          if fragments.exists(_.isEmpty) then false // not fully cached: fall back to a normal parse
          else
            new FragmentSplicePass(
              cpg,
              fragments.flatten,
              ts => ts.foreach(CGlobal.usedTypes.putIfAbsent(_, true))
            ).createAndApply()
            true
        end if

  /** `--macro-census` alone: write the report and a reviewable `--macro-files` header, no CPG. */
  def writeMacroCensus(config: Config): Unit =
    val report = MacroCensus.run(config)
    C2Cpg.writeReport(config, report)
    println(report.summary())

  def printIfDefsOnly(config: Config): Unit =
    val stmts = new PreprocessorPass(config).run().mkString(",")
    println(stmts)
end C2Cpg

object C2Cpg:

  /** The census (opt-in): with `--auto-defines` its auto tier joins the user's defines - a name the
    * user defined, undefined or left in a `--macro-files`/`--include-files` file is never
    * overridden. The report is written whenever a path is given. Shared by every C frontend entry.
    */
  def withCensusDefines(config: Config): Config =
      if !config.autoDefines && config.macroCensusReport.isEmpty then config
      else
        val report = MacroCensus.run(config)
        writeReport(config, report)
        if !config.autoDefines then config
        else
          println(report.summary())
          if report.auto.nonEmpty then
            println(s"Auto-defines: ${report.auto.map(_.name).mkString(" ")}")
          config.withDefines(config.defines ++ report.autoDefines)

  /** Write `<base>.json` and `<base>.h`, creating the directory; a failure is reported, never fatal
    * to the analysis.
    */
  def writeReport(config: Config, report: MacroCensus.Report): Unit =
      MacroCensus.reportPaths(config) match
        case List(json, header) =>
            try
              Option(json.toAbsolutePath.getParent).foreach(Files.createDirectories(_))
              Files.writeString(json, report.toJson)
              Files.writeString(header, report.toMacroHeader)
              println(s"Macro census written to $json and $header (use --macro-files $header)")
            catch
              case e: java.io.IOException =>
                  System.err.println(s"Macro census: cannot write $json / $header: ${e.getMessage}")
        case _ => ()
end C2Cpg
