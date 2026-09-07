package io.appthreat.ruby2atom.testfixtures

import io.appthreat.ruby2atom.astcreation.AstCreator
import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst
import io.appthreat.ruby2atom.parser.{RubyJsonParser, RubyJsonToNodeCreator, ParserKeys}
import io.appthreat.ruby2atom.passes.ConfigFileCreationPass
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.frontend.{MetaDataPass, TypeNodePass}
import io.appthreat.x2cpg.{ValidationMode, *}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import org.scalatest.{BeforeAndAfterAll, Inside}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.slf4j.LoggerFactory
import overflowdb.BatchedUpdate

import java.nio.file.{Files, Path, Paths}
import scala.collection.mutable
import scala.util.Using

/** Builds real CPGs for ruby2atom tests from committed fixture pairs under
  * `src/test/resources/ruby`: each fixture is a Ruby source file plus the JSON emitted for it by
  * `rbastgen` (ruby_ast_gen v2.1.0, see `resources/ruby/README.md`).
  *
  * The harness is modelled on php2atom's `PhpCode2CpgFixture` — php2atom is the frontend sharing
  * ruby2atom's architecture (a generator binary writes astgen JSON, the frontend rebuilds an
  * intermediate AST from it). It differs in one deliberate way: instead of shelling out to
  * `rbastgen` at test time, it ingests the committed JSON. The released `rbastgen` on a developer's
  * PATH may lag the generator branch these fixtures were generated with, and the committed JSON
  * pins the exact bytes the tests were written against. Regenerate with
  * `resources/ruby/regenerate_fixtures.sh`.
  */
object Ruby2AtomFixture:

  private val logger = LoggerFactory.getLogger(getClass)

  case class BuiltFixture(
    cpg: Cpg,
    /** Per-file reports of node types that degraded to `Unknown` or arrived truncated. */
    unknownTypes: Map[String, Int]
  )

  /** Builds one CPG containing all the named fixtures (order preserved), mirroring the pass
    * sequence of `Ruby2Atom.createCpg`.
    */
  def build(fixtureNames: String*): BuiltFixture =
    val tmpDir      = Files.createTempDirectory("ruby2atomFixture")
    val cpg         = Cpg.emptyCpg
    val allUnknowns = mutable.Map.empty[String, Int]
    try
      new MetaDataPass(cpg, Languages.RUBYSRC, tmpDir.toString).createAndApply()
      new ConfigFileCreationPass(cpg).createAndApply()
      // Phase 1: parse every fixture, aggregating the unknown-type reports.
      val parsed = fixtureNames.toList.map { fixtureName =>
        val jsonPath     = materializeFixture(fixtureName, tmpDir)
        val parserResult = RubyJsonParser.readFile(jsonPath)
        val creator      = new RubyJsonToNodeCreator(fileName = parserResult.fullPath)
        val program      = creator.visitProgram(parserResult.json)
        creator.unknownTypeReport.foreach { case (k, n) =>
            allUnknowns.updateWith(k)((old) => Some(old.getOrElse(0) + n))
        }
        (parserResult.filename, parserResult.fullPath, program)
      }
      // Phase 2: the program summary feeds scope resolution during AST creation, mirroring
      // Ruby2Atom.createCpgAction.
      val programSummary = io.appthreat.ruby2atom.datastructures.RubyProgramSummaryBuilder.build(
        parsed.map((relPath, _, program) => relPath -> program)
      )
      parsed.foreach { (_, fullPath, program) =>
        val astCreator = new AstCreator(
          fileName = fullPath,
          projectRoot = Option(tmpDir.toString),
          programSummary = programSummary,
          enableFileContents = false,
          rootNode = program
        )(using ValidationMode.Enabled)
        BatchedUpdate.applyDiff(cpg.graph, astCreator.createAst())
      }
      // Pass order mirrors Ruby2Atom.createCpgAction: the import passes add nodes whose types
      // TypeNodePass then materializes, so TypeNodePass runs last.
      new io.appthreat.x2cpg.frontendspecific.ruby2atom.ImportsPass(cpg).createAndApply()
      new io.appthreat.x2cpg.frontendspecific.ruby2atom.ImplicitRequirePass(cpg).createAndApply()
      TypeNodePass.withTypesFromCpg(cpg).createAndApply()
      X2Cpg.applyDefaultOverlays(cpg)
      BuiltFixture(cpg, allUnknowns.toMap)
    catch
      case t: Throwable =>
          cpg.close()
          throw t
    finally
      deleteRecursively(tmpDir)
    end try
  end build

  /** Copies `<name>.rb` and its generated `<name>.rb.json` from the test resources into `tmpDir`,
    * rewriting the JSON's `file_path` to the copied source. `RubyJsonParser.readFile` re-reads the
    * source from that absolute path, exactly as a real ingest does.
    */
  private def materializeFixture(fixtureName: String, tmpDir: Path): Path =
    val sourceResource = s"/ruby/$fixtureName.rb"
    val resourceStream = Option(getClass.getResourceAsStream(s"/ruby/$fixtureName.rb.json"))
    val sourceStream   = Option(getClass.getResourceAsStream(sourceResource))
    require(resourceStream.isDefined, s"missing test resource $fixtureName.rb.json")
    require(sourceStream.isDefined, s"missing test resource $fixtureName.rb")

    val targetSource = tmpDir.resolve(s"$fixtureName.rb")
    if targetSource.getParent != null then Files.createDirectories(targetSource.getParent)
    Using.resource(sourceStream.get)(Files.copy(_, targetSource))
    val targetJson = tmpDir.resolve(s"$fixtureName.rb.json")
    Using.resource(resourceStream.get) { jsonStream =>
      val json = ujson.read(new String(jsonStream.readAllBytes(), "UTF-8"))
      json(ParserKeys.FilePath) = targetSource.toAbsolutePath.toString
      Files.write(targetJson, ujson.write(json).getBytes("UTF-8"))
    }
    targetJson

  private def deleteRecursively(dir: Path): Unit =
      if Files.exists(dir) then
        Files.walk(dir).sorted(java.util.Comparator.reverseOrder[Path]()).forEach(Files.delete(_))

  /** Parses fixtures without building a CPG, as (require-style relative path, program) pairs - the
    * input shape of `RubyProgramSummaryBuilder.build`.
    */
  def parse(fixtureNames: String*): List[(String, RubyIntermediateAst.StatementList)] =
    val tmpDir = Files.createTempDirectory("ruby2atomParse")
    try
        fixtureNames.toList.map { fixtureName =>
          val jsonPath     = materializeFixture(fixtureName, tmpDir)
          val parserResult = RubyJsonParser.readFile(jsonPath)
          val program = new RubyJsonToNodeCreator(fileName = parserResult.fullPath)
              .visitProgram(parserResult.json)
          parserResult.filename.stripSuffix(".rb") -> program
        }
    finally deleteRecursively(tmpDir)
end Ruby2AtomFixture

/** Base class for ruby2atom specs: tests call `fixture("it_block")` to obtain a CPG built from
  * `src/test/resources/ruby/it_block.rb(.json)`, then assert on CPG nodes.
  */
class RubyCode2CpgFixture
    extends AnyWordSpec
    with Matchers
    with Inside
    with BeforeAndAfterAll:

  private val builtCpgs = mutable.ArrayBuffer.empty[Cpg]

  /** Builds (or returns the cached) CPG for the given fixture names.
    */
  def fixture(fixtureNames: String*): Cpg =
    val built = Ruby2AtomFixture.build(fixtureNames*)
    builtCpgs.append(built.cpg)
    built.cpg

  /** Builds the CPG and additionally asserts that no node silently degraded to `Unknown`.
    */
  def fixtureWithoutUnknowns(fixtureNames: String*): Cpg =
    val built = Ruby2AtomFixture.build(fixtureNames*)
    built.unknownTypes shouldBe empty
    builtCpgs.append(built.cpg)
    built.cpg

  /** Exposes the unknown-type report for fixtures that are *expected* to degrade.
    */
  def fixtureWithReport(fixtureNames: String*): (Cpg, Map[String, Int]) =
    val built = Ruby2AtomFixture.build(fixtureNames*)
    builtCpgs.append(built.cpg)
    (built.cpg, built.unknownTypes)

  override def afterAll(): Unit =
    builtCpgs.foreach(_.close())
    builtCpgs.clear()
end RubyCode2CpgFixture
