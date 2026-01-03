package io.appthreat.c2cpg.passes.ast

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.passes.AstCreationPass
import io.appthreat.c2cpg.testfixtures.AbstractPassTest
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.shiftleft.codepropertygraph.Cpg
import overflowdb.BatchedUpdate.DiffGraphBuilder
import better.files.File

import java.nio.file.{Files, Path, Paths}
import scala.jdk.CollectionConverters.*

class AstCacheTests extends AbstractPassTest {

    /**
     * Custom fixture that exposes the temporary directory path.
     */
    private def withTempScope(code: String, fileName: String = "file.c")(f: (Cpg, Path) => Unit): Unit = {
        File.usingTemporaryDirectory("c2cpg-test-scope") { dir =>
            val cpg = newEmptyCpg()
            val file = dir / fileName
            file.write(code)
            f(cpg, dir.path)
        }
    }

    private def createConfig(inputPath: Path, cacheDir: Path): Config = {
        Config()
            .withInputPath(inputPath.toString)
            .withAstCache(true)
            .withCacheDir(cacheDir.toString)
    }

    private def withCacheDir[T](f: Path => T): T = {
        val tempDir = Files.createTempDirectory("c2cpg-cache-storage")
        try {
            f(tempDir)
        } finally {
            Files.walk(tempDir)
                .sorted(java.util.Comparator.reverseOrder())
                .map(_.toFile)
                .forEach(_.delete())
        }
    }

    "AST Caching" should {

        "save AST to disk on first run" in withCacheDir { cacheDir =>
            withTempScope("""void foo() { int x = 1; }""") { (cpg, rootDir) =>
                val config = createConfig(rootDir, cacheDir)
                val pass = new AstCreationPass(cpg, config)
                val diffGraph = new DiffGraphBuilder
                val filename = rootDir.resolve("file.c").toAbsolutePath.toString

                pass.runOnPart(diffGraph, filename)

                val cacheFiles = Files.list(cacheDir).iterator().asScala.toList
                cacheFiles.size shouldBe 1
                cacheFiles.head.toString should endWith(".ast")
            }
        }

        "reuse AST from disk on second run" in withCacheDir { cacheDir =>
            withTempScope("""void foo() { int y = 2; }""") { (cpg, rootDir) =>
                val config = createConfig(rootDir, cacheDir)
                val pass = new AstCreationPass(cpg, config)
                val filename = rootDir.resolve("file.c").toAbsolutePath.toString

                pass.runOnPart(new DiffGraphBuilder, filename)

                val cacheFiles = Files.list(cacheDir).iterator().asScala.toList
                cacheFiles.size shouldBe 1
                val cacheFile = cacheFiles.head
                val lastModifiedTime = Files.getLastModifiedTime(cacheFile)

                Thread.sleep(100)

                pass.runOnPart(new DiffGraphBuilder, filename)

                Files.getLastModifiedTime(cacheFile) shouldBe lastModifiedTime
            }
        }

        "invalidate cache if file content changes" in withCacheDir { cacheDir =>
            withTempScope("""void a() {}""") { (cpg, rootDir) =>
                val config = createConfig(rootDir, cacheDir)
                val pass = new AstCreationPass(cpg, config)
                val filePath = rootDir.resolve("file.c")
                val filename = filePath.toAbsolutePath.toString

                pass.runOnPart(new DiffGraphBuilder, filename)

                val cacheFiles1 = Files.list(cacheDir).iterator().asScala.map(_.getFileName.toString).toList
                cacheFiles1.size shouldBe 1
                val hash1 = cacheFiles1.head

                Files.writeString(filePath, "void b() {}")

                pass.runOnPart(new DiffGraphBuilder, filename)

                val cacheFiles2 = Files.list(cacheDir).iterator().asScala.map(_.getFileName.toString).toList

                cacheFiles2.size shouldBe 2
                cacheFiles2 should contain (hash1)
                cacheFiles2 should not contain only (hash1)
            }
        }
    }
}