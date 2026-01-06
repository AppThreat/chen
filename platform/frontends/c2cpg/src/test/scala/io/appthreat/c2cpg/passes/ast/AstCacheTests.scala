package io.appthreat.c2cpg.passes.ast

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.passes.AstCreationPass
import io.appthreat.c2cpg.testfixtures.AbstractPassTest
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.shiftleft.codepropertygraph.Cpg
import overflowdb.BatchedUpdate.DiffGraphBuilder
import better.files.File
import upickle.default.*

import java.nio.file.{Files, Path, Paths}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*
import scala.util.Try

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

    private def computeHash(path: Path): String = {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(path.toAbsolutePath.toString.getBytes("UTF-8"))
        digest.update(Files.readAllBytes(path))
        digest.digest().map("%02x".format(_)).mkString
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
                cacheFiles.head.toString should endWith(".json")
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

        "SECURITY: reject malicious class names in cache" in withCacheDir { cacheDir =>
            withTempScope("""void safe() {}""") { (cpg, rootDir) =>
                val config = createConfig(rootDir, cacheDir)
                val filePath = rootDir.resolve("file.c")
                val filename = filePath.toAbsolutePath.toString

                val hash = computeHash(filePath)
                val cacheFile = cacheDir.resolve(s"$hash.json")

                import AstCreationPass.{CachedAst, CachedNode}

                val maliciousNode = CachedNode("java.io.File", Map("path" -> ujson.Str("/tmp/hacked")))

                val maliciousAst = CachedAst(
                    rootIdx = Some(0),
                    nodes = List(maliciousNode),
                    edges = List.empty
                )

                val bytes = writeBinary(maliciousAst)
                Files.write(cacheFile, bytes)

                val pass = new AstCreationPass(cpg, config)
                val diffGraph = new DiffGraphBuilder

                noException should be thrownBy pass.runOnPart(diffGraph, filename)

                val newBytes = Files.readAllBytes(cacheFile)
                val newAst = readBinary[CachedAst](newBytes)

                val rootNode = newAst.nodes(newAst.rootIdx.get)
                rootNode.className should startWith ("io.shiftleft.codepropertygraph.generated.nodes")
            }
        }

        "SECURITY: handle corrupted cache data gracefully" in withCacheDir { cacheDir =>
            withTempScope("""void safe() {}""") { (cpg, rootDir) =>
                val config = createConfig(rootDir, cacheDir)
                val filePath = rootDir.resolve("file.c")
                val filename = filePath.toAbsolutePath.toString
                val hash = computeHash(filePath)
                val cacheFile = cacheDir.resolve(s"$hash.json")

                Files.writeString(cacheFile, "THIS IS NOT VALID MSG PACK DATA")

                val pass = new AstCreationPass(cpg, config)
                noException should be thrownBy pass.runOnPart(new DiffGraphBuilder, filename)

                val newBytes = Files.readAllBytes(cacheFile)
                Try(readBinary[AstCreationPass.CachedAst](newBytes)).isSuccess shouldBe true
            }
        }
    }
}