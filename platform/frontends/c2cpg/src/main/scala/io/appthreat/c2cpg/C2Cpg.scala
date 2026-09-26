package io.appthreat.c2cpg

import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.passes.{
    AstCreationPass,
    ConfigFileCreationPass,
    PreprocessorPass,
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

import io.appthreat.c2cpg.parser.MacroCensus

import java.nio.file.{Files, Paths}
import scala.util.Try

class C2Cpg extends X2CpgFrontend[Config]:

  def createCpg(config: Config): Try[Cpg] =
      withNewEmptyCpg(config.outputPath, config) { (cpg, config) =>
        new MetaDataPass(cpg, Languages.NEWC, config.inputPath).createAndApply()
        val updatedConfig = if config.includePathsAutoDiscovery then
          val projectIncludes =
              IncludeAutoDiscovery.discoverProjectIncludePaths(Paths.get(config.inputPath))
          if projectIncludes.nonEmpty then
            println(s"Auto-discovered ${projectIncludes.size} project include paths")
          config.withIncludePaths(config.includePaths ++ projectIncludes.map(_.toString))
        else
          config
        val censusConfig = withCensusDefines(updatedConfig)

        if !warmRestoreFromFragments(cpg, censusConfig) then
          new AstCreationPass(cpg, censusConfig).createAndApply()

        if !config.onlyAstCache then
          new ConfigFileCreationPass(cpg).createAndApply()
          TypeNodePass.withRegisteredTypes(CGlobal.typesSeen(), cpg).createAndApply()
          new TypeDeclNodePass(cpg)(using config.schemaValidation).createAndApply()
      }

  /** Fastest-splice warm restore (CHEN3_PLAN §3.4): when fragment caching is enabled (atom
    * `--flux`) and every source file is already cached as a `.frag`, reconstruct the AST layer by
    * splicing the cached mini-graphs straight into the graph - skipping parsing AND the diff-graph
    * rebuild - instead of running the parallel [[AstCreationPass]]. Returns false (so the normal
    * pass runs) when caching is off, in cache-warming mode, or the project is not fully cached.
    */
  private def warmRestoreFromFragments(cpg: Cpg, config: Config): Boolean =
      if !config.enableAstCache || config.onlyAstCache || !CacheControl.useFragments then false
      else
        val files = AstCreationPass.sourceFiles(config)
        if files.isEmpty then false
        else
          val store = new AstCacheStore(
            config.enableAstCache,
            resolveCacheDir(config.inputPath, config.cacheDir),
            config.onlyAstCache
          )
          val fragments =
              files.toSeq.map(f => store.fragmentFor(
                AstCreationPass.fileCacheKey(f),
                AstCreationPass.cacheFingerprint(config)
              ))
          if fragments.exists(_.isEmpty) then false // not fully cached: fall back to a normal parse
          else
            new FragmentSplicePass(
              cpg,
              fragments.flatten,
              ts => ts.foreach(CGlobal.usedTypes.putIfAbsent(_, true))
            ).createAndApply()
            true

  /** The census (opt-in): with `--auto-defines` its auto tier joins the user's defines - a user
    * `--define` of the same name wins, the census never overrides one. The report is written
    * whenever a path is given.
    */
  private def withCensusDefines(config: Config): Config =
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

  /** `--macro-census` alone: write the report and a reviewable `--macro-files` header, no CPG. */
  def writeMacroCensus(config: Config): Unit =
    val report = MacroCensus.run(config)
    writeReport(config, report)
    println(report.summary())

  private def writeReport(config: Config, report: MacroCensus.Report): Unit =
      if config.macroCensusReport.nonEmpty then
        val base = config.macroCensusReport.stripSuffix(".json")
        Files.writeString(Paths.get(s"$base.json"), report.toJson)
        Files.writeString(Paths.get(s"$base.h"), report.toMacroHeader)
        println(s"Macro census written to $base.json and $base.h (use --macro-files $base.h)")

  def printIfDefsOnly(config: Config): Unit =
    val stmts = new PreprocessorPass(config).run().mkString(",")
    println(stmts)
end C2Cpg
