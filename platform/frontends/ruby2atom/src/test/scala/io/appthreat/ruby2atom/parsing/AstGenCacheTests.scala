package io.appthreat.ruby2atom.parsing

import better.files.File
import io.appthreat.ruby2atom.Config
import io.appthreat.ruby2atom.parser.RubyAstGenRunner
import io.appthreat.x2cpg.astgen.AstGenRunner.{
    AstGenProgramMetaData,
    AstGenRunnerResult,
    DefaultAstGenRunnerResult
}
import io.appthreat.x2cpg.passes.frontend.CacheControl
import org.scalatest.BeforeAndAfterEach
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files
import java.nio.file.attribute.FileTime

class AstGenCacheTests extends AnyWordSpec with Matchers with BeforeAndAfterEach:

  override def afterEach(): Unit = CacheControl.enableAll()

  /** A runner that does not start rbastgen: it writes one AST file and counts what the
    * cache-related steps do, so a test sees which of them ran without timing anything.
    */
  private class CountingRunner(config: Config) extends RubyAstGenRunner(config):
    var fingerprints  = 0
    var generatorRuns = 0

    override private[ruby2atom] def astGenFingerprint(excludeRegex: String): String =
      fingerprints += 1
      super.astGenFingerprint(excludeRegex)

    override def runAstGenNative(in: String, out: File, exclude: String, include: String)(implicit
      metaData: AstGenProgramMetaData
    ): AstGenRunnerResult =
      generatorRuns += 1
      val ast = (out / "a.rb.json").createFileIfNotExists(createParents = true)
      ast.writeText("{}")
      DefaultAstGenRunnerResult(List(ast.pathAsString))

  private def project(): File =
    val dir = File.newTemporaryDirectory("rbastgen-cache-proj")
    (dir / "a.rb").writeText("x = 1\n")
    dir

  private def execute(runner: RubyAstGenRunner): File =
    val out = File.newTemporaryDirectory("rbastgen-cache-out")
    runner.execute(out)
    out

  private def setTime(file: File, millis: Long): Unit =
      Files.setLastModifiedTime(file.path, FileTime.fromMillis(millis))

  "RubyAstGenRunner.execute" should {

      "compute no fingerprint while the astgen cache is off" in {
          val dir = project()
          CacheControl.disable(CacheControl.Astgen)
          val runner = new CountingRunner(Config().withInputPath(dir.pathAsString))
          execute(runner)
          runner.fingerprints shouldBe 0
          runner.generatorRuns shouldBe 1
          (dir / ".chen").exists shouldBe false
      }

      "compute no fingerprint while every cache is off" in {
          val dir = project()
          CacheControl.disableAll()
          val runner = new CountingRunner(Config().withInputPath(dir.pathAsString))
          execute(runner)
          runner.fingerprints shouldBe 0
          runner.generatorRuns shouldBe 1
      }

      "store the parse on the first run and restore it on the second when the cache is on" in {
          val dir   = project()
          val first = new CountingRunner(Config().withInputPath(dir.pathAsString))
          execute(first)
          first.fingerprints shouldBe 1
          first.generatorRuns shouldBe 1

          val second = new CountingRunner(Config().withInputPath(dir.pathAsString))
          val out    = execute(second)
          second.fingerprints shouldBe 1
          second.generatorRuns shouldBe 0
          (out / "a.rb.json").exists shouldBe true

          (dir / "a.rb").writeText("x = 2\n")
          val third = new CountingRunner(Config().withInputPath(dir.pathAsString))
          execute(third)
          third.generatorRuns shouldBe 1
      }
  }

  "the rbastgen cache fingerprint" should {

      def fingerprint(dir: File, exclude: String = ""): String =
          new RubyAstGenRunner(Config().withInputPath(dir.pathAsString)).astGenFingerprint(exclude)

      "read project files by content" in {
          val dir    = project()
          val time   = Files.getLastModifiedTime((dir / "a.rb").path).toMillis
          val before = fingerprint(dir)
          (dir / "a.rb").writeText("x = 3\n")
          setTime(dir / "a.rb", time)
          fingerprint(dir) should not be before
      }

      "leave out .git and the files the exclude pattern covers, which rbastgen never opens" in {
          val dir = project()
          (dir / "spec" / "a_spec.rb").createFileIfNotExists(true).writeText("a")
          val exclude = "(^|/)spec($|/)"
          val before  = fingerprint(dir, exclude)

          (dir / ".git" / "HEAD").createFileIfNotExists(true).writeText("ref")
          (dir / "spec" / "a_spec.rb").writeText("changed")
          (dir / "spec" / "other.rb").createFileIfNotExists(true).writeText("new")
          fingerprint(dir, exclude) shouldBe before

          // without the pattern the same files count, and a pattern change is a different key
          fingerprint(dir, "") should not be before
          (dir / "a.rb").writeText("x = 4\n")
          fingerprint(dir, exclude) should not be before
      }

      "match the pattern against the path relative to the input, so the input's own path is not excluded" in {
          val dir = File.newTemporaryDirectory("tests-rbastgen")
          (dir / "a.rb").writeText("x = 1\n")
          val before = fingerprint(dir, "tests?")
          (dir / "a.rb").writeText("x = 2\n")
          fingerprint(dir, "tests?") should not be before
      }

      "leave nothing out for a pattern Java cannot compile" in {
          val dir    = project()
          val before = fingerprint(dir, "(unclosed")
          (dir / "a.rb").writeText("x = 5\n")
          fingerprint(dir, "(unclosed") should not be before
      }
  }
end AstGenCacheTests
