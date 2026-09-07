package io.appthreat.ruby2atom.parsing

import better.files.File
import io.appthreat.ruby2atom.{Config, Ruby2Atom}
import io.appthreat.ruby2atom.parser.RubyAstGenRunner
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Paths}

/** The generator binary can be overridden without touching `PATH`, so a custom `rbastgen` build can
  * be used when ruby2atom runs inside another process (atom loads it as a library, so it inherits
  * that process's `PATH` and cannot be pointed at a different binary otherwise).
  */
class AstGenProgramTests extends AnyWordSpec with Matchers:

  "the generator program" should {

      "default to the PATH lookup" in {
          RubyAstGenRunner.resolveProgram(None, None) shouldBe "rbastgen"
      }

      "prefer the system property over the environment" in {
          RubyAstGenRunner.resolveProgram(
            Some("/opt/custom/rbastgen"),
            Some("/usr/bin/rbastgen")
          ) shouldBe "/opt/custom/rbastgen"
      }

      "fall back to the environment variable" in {
          RubyAstGenRunner.resolveProgram(
            None,
            Some("/usr/bin/rbastgen")
          ) shouldBe "/usr/bin/rbastgen"
      }

      "treat blank values as unset" in {
          RubyAstGenRunner.resolveProgram(Some("  "), Some("")) shouldBe "rbastgen"
      }
  }

  "the generator's side-records" should {

      "not enter the AST path when they sit in the output directory" in {
          // A 2.x run leaves both side-records beside the AST files. The AST collection globs
          // the output dir with `Set(".json")` and hands every match to RubyJsonParser.readFile,
          // which requires a top-level file_path; a failure there is swallowed downstream, so a
          // naming regression would silently miscount a run rather than crash. Pin the exact set
          // through the same `astFilesIn` the production collectResult uses.
          val out    = Files.createTempDirectory("ruby2atomSideRecords")
          val source = out.resolve("one.rb")
          Files.writeString(source, "x = 1\n")
          val astJson = ujson.Obj(
            "type" -> "begin",
            "body" -> ujson.Arr(),
            // meta_data carries the seven keys every generator-emitted node has (toTextSpan reads it).
            "meta_data" -> ujson.Obj(
              "code"         -> "x = 1",
              "start_line"   -> 1,
              "start_column" -> 0,
              "end_line"     -> 1,
              "end_column"   -> 6,
              "offset_start" -> 0,
              "offset_end"   -> 6
            ),
            "file_path"         -> source.toAbsolutePath.toString,
            "rel_file_path"     -> "one.rb",
            "generator_version" -> "2.1.0"
          )
          Files.writeString(out.resolve("one.rb.json"), ujson.write(astJson))
          Files.writeString(
            out.resolve(RubyAstGenRunner.ManifestFilename),
            """{"input":"/tmp/project","files_parsed":1,"files_failed":0}"""
          )
          Files.writeString(
            out.resolve(RubyAstGenRunner.DiagnosticsFilename),
            """{"file_path":"/tmp/project/bad.rb","rel_file_path":"bad.rb","parse_error":{"message":"unexpected token","line":1,"column":8,"diagnostic_reason":"unexpected_token"}}"""
          )

          val astFiles = RubyAstGenRunner.astFilesIn(File(out.toString), Config())
          astFiles.map(fileName => Paths.get(fileName).getFileName.toString) shouldBe List(
            "one.rb.json"
          )

          // The whole collected set parses: one file, nothing from the side-records.
          val parsed = Ruby2Atom.parseAstGenResults(astFiles).toList.map(_())
          parsed.map(_.relativeFilePath) shouldBe List("one.rb")
      }

      "have their manifest counts read, with missing or malformed records tolerated" in {
          val out = Files.createTempDirectory("ruby2atomManifest")
          Files.writeString(
            out.resolve(RubyAstGenRunner.ManifestFilename),
            """{"input":"/tmp/project","files_parsed":3,"files_failed":1}"""
          )
          val counts = RubyAstGenRunner.readRunManifest(out)
          counts.map(_.filesParsed) shouldBe Some(3)
          counts.map(_.filesFailed) shouldBe Some(1)
          counts.map(_.input) shouldBe Some("/tmp/project")

          // A 1.x generator writes no manifest, and a broken record must not fail a run.
          RubyAstGenRunner.readRunManifest(
            Files.createTempDirectory("ruby2atomNoManifest")
          ) shouldBe None
          val malformed = Files.createTempDirectory("ruby2atomManifestBad")
          Files.writeString(malformed.resolve(RubyAstGenRunner.ManifestFilename), "{not json")
          RubyAstGenRunner.readRunManifest(malformed) shouldBe None
      }

      "report the diagnostics record count when present" in {
          val out = Files.createTempDirectory("ruby2atomDiagnostics")
          Files.writeString(
            out.resolve(RubyAstGenRunner.DiagnosticsFilename),
            "{\"a\":1}\n{\"b\":2}\n"
          )
          RubyAstGenRunner.diagnosticsRecordCount(out) shouldBe Some(2)
          RubyAstGenRunner.diagnosticsRecordCount(
            Files.createTempDirectory("ruby2atomNoDiagnostics")
          ) shouldBe None
      }
  }
end AstGenProgramTests
