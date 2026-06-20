package io.appthreat.c2cpg.passes.ast

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.passes.AstCreationPass
import io.appthreat.c2cpg.testfixtures.AbstractPassTest
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.appthreat.x2cpg.AstCache
import io.appthreat.x2cpg.AstCache.{AstBitcode, AstNodeBitcode}
import io.shiftleft.codepropertygraph.Cpg
import overflowdb.BatchedUpdate.DiffGraphBuilder
import better.files.File
import upickle.default.*

import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*
import scala.util.Try

class AstCacheTests extends AbstractPassTest:

  /** Custom fixture that exposes the temporary directory path.
    */
  private def withTempScope(
    code: String,
    fileName: String = "file.c"
  )(f: (Cpg, Path) => Unit): Unit =
      File.usingTemporaryDirectory("c2cpg-test-scope") { dir =>
        val cpg  = newEmptyCpg()
        val file = dir / fileName
        file.write(code)
        f(cpg, dir.path)
      }

  private def createConfig(inputPath: Path, cacheDir: Path): Config =
      Config()
          .withInputPath(inputPath.toString)
          .withAstCache(true)
          .withCacheDir(cacheDir.toString)

  private def withCacheDir[T](f: Path => T): T =
    val tempDir = Files.createTempDirectory("c2cpg-cache-storage")
    try
        f(tempDir)
    finally
        Files.walk(tempDir)
            .sorted(java.util.Comparator.reverseOrder())
            .map(_.toFile)
            .forEach(_.delete())

  private def computeHash(path: Path): String =
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(path.toAbsolutePath.toString.getBytes("UTF-8"))
    digest.update(Files.readAllBytes(path))
    digest.digest().map("%02x".format(_)).mkString

  "AST Caching" should {

      "save AST to disk on first run" in withCacheDir { cacheDir =>
          withTempScope("""void foo() { int x = 1; }""") { (cpg, rootDir) =>
            val config    = createConfig(rootDir, cacheDir)
            val pass      = new AstCreationPass(cpg, config)
            val diffGraph = new DiffGraphBuilder
            val filename  = rootDir.resolve("file.c").toAbsolutePath.toString

            pass.runOnPart(diffGraph, filename)

            val cacheFiles = Files.list(cacheDir).iterator().asScala.toList
            cacheFiles.size shouldBe 1
            cacheFiles.head.toString should endWith(".ast")
          }
      }

      "write no cache when the AST cache is globally disabled via CacheControl" in withCacheDir {
          cacheDir =>
              withTempScope("""void foo() { int x = 1; }""") { (cpg, rootDir) =>
                val config   = createConfig(rootDir, cacheDir)
                val filename = rootDir.resolve("file.c").toAbsolutePath.toString
                try
                  io.appthreat.x2cpg.passes.frontend.CacheControl.disable(
                    io.appthreat.x2cpg.passes.frontend.CacheControl.Ast
                  )
                  new AstCreationPass(cpg, config).runOnPart(new DiffGraphBuilder, filename)
                  Files.list(cacheDir).iterator().asScala.toList shouldBe empty
                finally
                  io.appthreat.x2cpg.passes.frontend.CacheControl.enable(
                    io.appthreat.x2cpg.passes.frontend.CacheControl.Ast
                  )
              }
      }

      "reuse AST from disk on second run" in withCacheDir { cacheDir =>
          withTempScope("""void foo() { int y = 2; }""") { (cpg, rootDir) =>
            val config   = createConfig(rootDir, cacheDir)
            val pass     = new AstCreationPass(cpg, config)
            val filename = rootDir.resolve("file.c").toAbsolutePath.toString

            pass.runOnPart(new DiffGraphBuilder, filename)

            val cacheFiles = Files.list(cacheDir).iterator().asScala.toList
            cacheFiles.size shouldBe 1
            val cacheFile        = cacheFiles.head
            val lastModifiedTime = Files.getLastModifiedTime(cacheFile)

            Thread.sleep(100)

            pass.runOnPart(new DiffGraphBuilder, filename)

            Files.getLastModifiedTime(cacheFile) shouldBe lastModifiedTime
          }
      }

      "re-register types on a cache hit so TYPE nodes are not lost" in withCacheDir { cacheDir =>
          withTempScope("""long foo(int x) { char c = 'a'; return x; }""") { (_, rootDir) =>
            val config   = createConfig(rootDir, cacheDir)
            val filename = rootDir.resolve("file.c").toAbsolutePath.toString

            // cold run (cache miss): types are registered while parsing
            io.appthreat.c2cpg.datastructures.CGlobal.usedTypes.clear()
            new AstCreationPass(newEmptyCpg(), config).runOnPart(new DiffGraphBuilder, filename)
            val typesAfterCold =
                io.appthreat.c2cpg.datastructures.CGlobal.usedTypes.keySet().asScala.toSet
            typesAfterCold should not be empty

            // warm run (cache hit) in a "fresh process": the global table starts empty and must
            // be repopulated from the cache, otherwise the type node pass would create no TYPE nodes
            io.appthreat.c2cpg.datastructures.CGlobal.usedTypes.clear()
            new AstCreationPass(newEmptyCpg(), config).runOnPart(new DiffGraphBuilder, filename)
            val typesAfterWarm =
                io.appthreat.c2cpg.datastructures.CGlobal.usedTypes.keySet().asScala.toSet

            typesAfterWarm shouldBe typesAfterCold
          }
      }

      "invalidate cache if file content changes" in withCacheDir { cacheDir =>
          withTempScope("""void a() {}""") { (cpg, rootDir) =>
            val config   = createConfig(rootDir, cacheDir)
            val pass     = new AstCreationPass(cpg, config)
            val filePath = rootDir.resolve("file.c")
            val filename = filePath.toAbsolutePath.toString

            pass.runOnPart(new DiffGraphBuilder, filename)

            val cacheFiles1 =
                Files.list(cacheDir).iterator().asScala.map(_.getFileName.toString).toList
            cacheFiles1.size shouldBe 1
            val hash1 = cacheFiles1.head

            Files.writeString(filePath, "void b() {}")

            pass.runOnPart(new DiffGraphBuilder, filename)

            val cacheFiles2 =
                Files.list(cacheDir).iterator().asScala.map(_.getFileName.toString).toList

            cacheFiles2.size shouldBe 2
            cacheFiles2 should contain(hash1)
            cacheFiles2 should not contain only(hash1)
          }
      }

      "discard and recompute caches written by an incompatible build" in withCacheDir { cacheDir =>
          withTempScope("""void safe() {}""") { (cpg, rootDir) =>
            val config   = createConfig(rootDir, cacheDir)
            val filePath = rootDir.resolve("file.c")
            val filename = filePath.toAbsolutePath.toString

            val hash      = computeHash(filePath)
            val cacheFile = cacheDir.resolve(s"$hash.ast")

            // a cache from an incompatible (future) format version must never be loaded
            val staleAst = AstBitcode(
              formatTag = AstCache.FormatTag,
              formatVersion = AstCache.FormatVersion + 1,
              nodes = List(AstNodeBitcode("LITERAL", List.empty)),
              edges = List.empty
            )
            Files.write(cacheFile, writeBinary(staleAst))

            val pass = new AstCreationPass(cpg, config)

            noException should be thrownBy pass.runOnPart(new DiffGraphBuilder, filename)

            // the stale cache must have been discarded and replaced by a compatible one
            val reloaded = readBinary[AstBitcode](Files.readAllBytes(cacheFile))
            AstCache.isCompatible(reloaded) shouldBe true
          }
      }

      "SECURITY: handle corrupted cache data gracefully" in withCacheDir { cacheDir =>
          withTempScope("""void safe() {}""") { (cpg, rootDir) =>
            val config    = createConfig(rootDir, cacheDir)
            val filePath  = rootDir.resolve("file.c")
            val filename  = filePath.toAbsolutePath.toString
            val hash      = computeHash(filePath)
            val cacheFile = cacheDir.resolve(s"$hash.ast")

            Files.writeString(cacheFile, "THIS IS NOT VALID MSG PACK DATA")

            val pass = new AstCreationPass(cpg, config)
            noException should be thrownBy pass.runOnPart(new DiffGraphBuilder, filename)

            val newBytes = Files.readAllBytes(cacheFile)
            Try(readBinary[AstBitcode](newBytes)).isSuccess shouldBe true
          }
      }
  }
end AstCacheTests
