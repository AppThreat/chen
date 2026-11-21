package io.appthreat.jssrc2cpg.utils

import better.files.File
import io.appthreat.jssrc2cpg.Config
import io.appthreat.x2cpg.passes.frontend.CacheControl
import org.scalatest.BeforeAndAfterEach
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files
import java.nio.file.attribute.FileTime
import scala.util.{Success, Try}

class AstGenRunnerCacheTests extends AnyWordSpec with Matchers with BeforeAndAfterEach:

  override def afterEach(): Unit = CacheControl.enableAll()

  /** An astgen runner that does not start astgen: it writes one AST file and counts what the
    * cache-related steps do, so a test sees which of them ran without timing anything.
    */
  private class CountingRunner(config: Config) extends AstGenRunner(config):
    var versionProbes = 0
    var astGenRuns    = 0

    override private[utils] def astGenFingerprintInputs: Seq[String] =
      versionProbes += 1
      Seq("astgen-version=test")

    override private[utils] def runAstGenNative(in: File, out: File): Try[Seq[String]] =
      astGenRuns += 1
      (out / "a.js.json").createFileIfNotExists(createParents = true).writeText("{}")
      Success(Seq.empty)

  private def project(): File =
    val dir = File.newTemporaryDirectory("astgen-cache-proj")
    (dir / "a.js").writeText("var a = 1;")
    dir

  private def execute(runner: AstGenRunner): File =
    val out = File.newTemporaryDirectory("astgen-cache-out")
    runner.execute(out)
    out

  "AstGenRunner.execute" should {

      "compute no fingerprint and start no version probe while the astgen cache is off" in {
          val dir = project()
          CacheControl.disable(CacheControl.Astgen)
          val runner = new CountingRunner(Config().withInputPath(dir.pathAsString))
          execute(runner)
          runner.versionProbes shouldBe 0
          runner.astGenRuns shouldBe 1
          (dir / ".chen").exists shouldBe false
      }

      "compute no fingerprint while every cache is off" in {
          val dir = project()
          CacheControl.disableAll()
          val runner = new CountingRunner(Config().withInputPath(dir.pathAsString))
          execute(runner)
          runner.versionProbes shouldBe 0
          runner.astGenRuns shouldBe 1
      }

      "store the parse on the first run and restore it on the second when the cache is on" in {
          val dir = project()
          CacheControl.enable(CacheControl.Astgen)
          val first = new CountingRunner(Config().withInputPath(dir.pathAsString))
          execute(first)
          first.versionProbes shouldBe 1
          first.astGenRuns shouldBe 1

          val second = new CountingRunner(Config().withInputPath(dir.pathAsString))
          val out    = execute(second)
          second.versionProbes shouldBe 1
          second.astGenRuns shouldBe 0
          (out / "a.js.json").exists shouldBe true

          // a changed source misses the cache
          (dir / "a.js").writeText("var a = 2;")
          val third = new CountingRunner(Config().withInputPath(dir.pathAsString))
          execute(third)
          third.astGenRuns shouldBe 1
      }
  }

  "the astgen cache fingerprint" should {

      def fingerprint(dir: File, config: Config = Config()): String =
          new CountingRunner(config.withInputPath(dir.pathAsString)).astGenFingerprint

      def setTime(file: File, millis: Long): Unit =
          Files.setLastModifiedTime(file.path, FileTime.fromMillis(millis))

      "describe node_modules by size and time and read the project's own files" in {
          val dir = project()
          val dep = (dir / "node_modules" / "dep" / "index.js").createFileIfNotExists(true)
          dep.writeText("AAAA")
          setTime(dep, 1_000_000L)
          val before = fingerprint(dir)

          dep.writeText("BBBB")
          setTime(dep, 1_000_000L)
          fingerprint(dir) shouldBe before

          setTime(dep, 2_000_000L)
          fingerprint(dir) should not be before

          val source = dir / "a.js"
          val time   = Files.getLastModifiedTime(source.path).toMillis
          val moved  = fingerprint(dir)
          source.writeText("var a = 3;")
          setTime(source, time)
          fingerprint(dir) should not be moved
      }

      "leave .git out" in {
          val dir    = project()
          val before = fingerprint(dir)
          (dir / ".git" / "objects" / "ab").createFileIfNotExists(true).writeText("object")
          fingerprint(dir) shouldBe before
      }

      "describe the files the configuration ignores by size and time, as astgen still reads them" in {
          val dir     = project()
          val ignored = (dir / "docs" / "x.js").createFileIfNotExists(true)
          ignored.writeText("AAAA")
          setTime(ignored, 1_000_000L)
          val config = Config().withIgnoredFilesRegex(".*[\\\\/]docs[\\\\/].*")
          val before = fingerprint(dir, config)

          ignored.writeText("BBBB")
          setTime(ignored, 1_000_000L)
          fingerprint(dir, config) shouldBe before

          setTime(ignored, 2_000_000L)
          fingerprint(dir, config) should not be before

          // without the ignore pattern the same file is read by content
          val unignored = fingerprint(dir)
          ignored.writeText("CCCC")
          setTime(ignored, 2_000_000L)
          fingerprint(dir) should not be unignored
      }
  }
end AstGenRunnerCacheTests
