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

import java.nio.file.Paths
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

        if !warmRestoreFromFragments(cpg, updatedConfig) then
          new AstCreationPass(cpg, updatedConfig).createAndApply()

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
              files.toSeq.map(f => store.fragmentFor(AstCreationPass.fileCacheKey(f), ""))
          if fragments.exists(_.isEmpty) then false // not fully cached: fall back to a normal parse
          else
            new FragmentSplicePass(
              cpg,
              fragments.flatten,
              ts => ts.foreach(CGlobal.usedTypes.putIfAbsent(_, true))
            ).createAndApply()
            true

  def printIfDefsOnly(config: Config): Unit =
    val stmts = new PreprocessorPass(config).run().mkString(",")
    println(stmts)
end C2Cpg
