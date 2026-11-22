package io.appthreat.c2cpg.worker

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.parse.{
    ParseFailureRecord,
    ParseReporter,
    ParseUnitRecord,
    UnitSettingsReporter
}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import upickle.default.*

import java.nio.file.{FileSystemException, Files, LinkOption, Path, Paths}
import scala.jdk.CollectionConverters.*

/** The opt-in worker mode: with `--c-isolate`, every unit is parsed by a worker process that hands
  * its AST to the run through the AST cache, so a worker that exits, hangs or runs out of memory
  * costs its unit alone, which the parse report names with the reason. A unit whose worker failed
  * is retried once in a fresh worker. Without the option nothing changes: the graph is the one the
  * in-process run builds.
  */
class CdtWorkerTests extends CCodeToCpgSuite(FileDefaults.C_EXT):

  private def fixtureDirOf(resource: String): File =
      File(Paths.get(getClass.getClassLoader.getResource(resource).toURI)).parent

  /** The units and the guarded header with the inline pair readers: the project the failure and
    * comparison tests read.
    */
  private val fixtureDir = fixtureDirOf("worker/separate-units/pair.h")

  /** The unit whose include resolves to nothing, beside an ordinary one: what a parse reports as
    * partly read, and what the record's journey out of the worker is tested with.
    */
  private val problemFixtureDir = fixtureDirOf("worker/preprocessor-problem/plain-counter.c")

  /** The functions of every file but the one a test fails, plus the header's inline pair readers:
    * what every test but the comparison reads from the graph.
    */
  private val survivingFunctions =
      Seq(
        "mask_for",
        "flag_set",
        "keep_low",
        "smaller",
        "larger",
        "first_of",
        "swap_ints",
        "pair_first"
      )

  private def failedFunctions = Seq("next_ticket", "tickets_issued")

  private def copyFixture(dir: File)(root: File): File = dir.copyToDirectory(root)

  /** Builds the fixture project in `root`, optionally in worker mode, with the parse report on and
    * a test-only worker failure naming `static-counter.c`. Returns the graph and, when the report
    * was on, the failure and unit records the run collected.
    */
  private def build(
    root: File,
    isolate: Boolean,
    failure: Option[String],
    report: Boolean,
    astCache: Boolean = true,
    compileCommands: Option[String] = None
  ): (Cpg, List[ParseFailureRecord], List[ParseUnitRecord]) =
    val out = File.newTemporaryFile("c2worker", ".bin")
    out.deleteOnExit()
    ParseReporter.reset()
    UnitSettingsReporter.reset()
    if report then System.setProperty("chen.parse.report", "1")
    failure.foreach(value => System.setProperty(CdtWorker.TestFailureProperty, value))
    try
      val cpg = new C2Cpg().createCpg(
        Config()
            .withInputPath(root.pathAsString)
            .withOutputPath(out.pathAsString)
            .withFunctionBodies(true)
            .withAstCache(astCache)
            .withCompileCommands(compileCommands.getOrElse(""))
            .withCIsolate(isolate)
      ).get
      val failures = if report then ParseReporter.records else Nil
      val units    = if report then UnitSettingsReporter.records else Nil
      ParseReporter.reset()
      UnitSettingsReporter.reset()
      (cpg, failures, units)
    finally
      System.clearProperty("chen.parse.report")
      System.clearProperty(CdtWorker.TestFailureProperty)
  end build

  /** The graph's nodes by label and edges by type, TAG nodes included: two graphs are the same
    * graph when this is equal. The tags the AST creator writes ride the worker boundary in the
    * cached entry, which is what decides the codec the isolated run writes, so they are part of
    * what the comparison must hold equal.
    */
  private def shapeOf(cpg: Cpg): (Map[String, Int], Map[String, Int]) =
    val nodes  = cpg.graph.nodes().asScala.toSeq
    val out    = nodes.flatMap(n => n.outE().asScala.toSeq)
    val labels = nodes.groupBy(_.label()).view.mapValues(_.size).toMap
    val edges  = out.groupBy(_.label()).view.mapValues(_.size).toMap
    (labels, edges)

  private def methodFullNames(cpg: Cpg): List[String] = cpg.method.fullName.l.sorted

  private def failureRecordsFor(records: List[ParseFailureRecord], file: String) =
      records.filter(_.file.endsWith(file))

  /** Creates a symbolic link at `link` pointing at `target`, skipping the test where the platform
    * refuses to create one.
    */
  private def symlink(link: Path, target: Path): Unit =
      try Files.createSymbolicLink(link, target)
      catch
        case e: UnsupportedOperationException =>
            assume(false, s"this platform cannot create symbolic links: ${e.getMessage}")
        case e: FileSystemException =>
            assume(false, s"this platform refused to create a symbolic link: ${e.getMessage}")

  "a unit whose worker exits" should {

      "leave every other file in the graph and report the unit once per attempt" in {
          File.usingTemporaryDirectory("c2worker-exit") { root =>
            copyFixture(fixtureDir)(root)
            val (cpg, records, _) =
                build(root, isolate = true, failure = Some(s"exit:static-counter.c"), report = true)
            try
              survivingFunctions.foreach(name =>
                  cpg.method.nameExact(name).l should not be empty
              )
              failedFunctions.foreach(name => cpg.method.nameExact(name).l shouldBe empty)
              val forUnit = failureRecordsFor(records, "static-counter.c")
              forUnit should have size 2 // the attempt and its single retry, not more
              forUnit.foreach(record => record.message should include("exited"))
              forUnit.count(_.message.contains("retry")) shouldBe 1
            finally cpg.close()
          }
      }
  }

  "a unit whose worker exceeds the parse timeout" should {

      "leave every other file in the graph and report the unit once per attempt" in {
          File.usingTemporaryDirectory("c2worker-loop") { root =>
            copyFixture(fixtureDir)(root)
            val (cpg, records, _) =
                build(root, isolate = true, failure = Some(s"loop:static-counter.c"), report = true)
            try
              survivingFunctions.foreach(name =>
                  cpg.method.nameExact(name).l should not be empty
              )
              failedFunctions.foreach(name => cpg.method.nameExact(name).l shouldBe empty)
              val forUnit = failureRecordsFor(records, "static-counter.c")
              forUnit should have size 2 // the attempt and its single retry, not more
              forUnit.foreach(record => record.message should include("timeout"))
              forUnit.count(_.message.contains("retry")) shouldBe 1
            finally cpg.close()
          }
      }
  }

  "a unit whose worker runs out of memory" should {

      "leave every other file in the graph and report the unit once per attempt" in {
          File.usingTemporaryDirectory("c2worker-oom") { root =>
            copyFixture(fixtureDir)(root)
            val (cpg, records, _) =
                build(root, isolate = true, failure = Some(s"oom:static-counter.c"), report = true)
            try
              survivingFunctions.foreach(name =>
                  cpg.method.nameExact(name).l should not be empty
              )
              failedFunctions.foreach(name => cpg.method.nameExact(name).l shouldBe empty)
              val forUnit = failureRecordsFor(records, "static-counter.c")
              forUnit should have size 2 // the attempt and its single retry, not more
              forUnit.foreach(record => record.message should include("memory"))
              forUnit.count(_.message.contains("retry")) shouldBe 1
            finally cpg.close()
          }
      }
  }

  "the isolated run" should {

      "build the same graph as the in-process run, cold and warm" in {
          File.usingTemporaryDirectory("c2worker-plain") { plainRoot =>
              File.usingTemporaryDirectory("c2worker-isolated") { isolatedRoot =>
                copyFixture(fixtureDir)(plainRoot)
                copyFixture(fixtureDir)(isolatedRoot)
                val (plain, _, _) =
                    build(plainRoot, isolate = false, failure = None, report = false)
                val (isolated, _, _) =
                    build(isolatedRoot, isolate = true, failure = None, report = false)
                try
                  // the creator tags the calls whose function a header declares: the fixture
                  // carries them, and the comparison below holds them equal across the boundary
                  isolated.tag.l should not be empty
                  shapeOf(plain) shouldBe shapeOf(isolated)
                  methodFullNames(plain) shouldBe methodFullNames(isolated)
                  // the run over the project the workers cached loads their entries, as a
                  // warm run loads entries written in the process
                  val (warm, _, _) =
                      build(isolatedRoot, isolate = true, failure = None, report = false)
                  try
                    shapeOf(warm) shouldBe shapeOf(isolated)
                    methodFullNames(warm) shouldBe methodFullNames(isolated)
                  finally warm.close()
                finally
                  plain.close()
                  isolated.close()
              }
          }
      }

      "still report how each unit is parsed" in {
          File.usingTemporaryDirectory("c2worker-units") { root =>
            copyFixture(fixtureDir)(root)
            val (cpg, _, units) = build(root, isolate = true, failure = None, report = true)
            try
              val unit = units.find(_.file.endsWith("min-max.c"))
              unit shouldBe defined
              unit.get.frontend shouldBe ParseReporter.Frontend.C
              unit.get.language shouldBe io.appthreat.x2cpg.parse.UnitSettingsReporter.Language.C
            finally cpg.close()
          }
      }
  }

  "an isolated run without the AST cache" should {

      "build the in-process graph and leave no cache entry in the project" in {
          File.usingTemporaryDirectory("c2worker-nocache-plain") { plainRoot =>
              File.usingTemporaryDirectory("c2worker-nocache-isolated") { isolatedRoot =>
                copyFixture(fixtureDir)(plainRoot)
                copyFixture(fixtureDir)(isolatedRoot)
                val (plain, _, _) =
                    build(
                      plainRoot,
                      isolate = false,
                      failure = None,
                      report = false,
                      astCache = false
                    )
                val (isolated, _, _) =
                    build(
                      isolatedRoot,
                      isolate = true,
                      failure = None,
                      report = false,
                      astCache = false
                    )
                try
                  shapeOf(plain) shouldBe shapeOf(isolated)
                  methodFullNames(plain) shouldBe methodFullNames(isolated)
                  isolatedRoot.listRecursively.filter(_.name.endsWith(".frag")).toList shouldBe empty
                finally
                  plain.close()
                  isolated.close()
              }
          }
      }
  }

  "a worker's reply file" should {

      "replace a symbolic link at the reply's name instead of writing through it" in {
          val replyDir = Files.createTempDirectory("c2worker-reply")
          val outside  = Files.createTempDirectory("c2worker-reply-target")
          val victim   = outside.resolve("victim.json")
          Files.writeString(victim, "PRECIOUS")
          val replyFile = replyDir.resolve("reply-1.json")
          symlink(replyFile, victim)
          // writeReply reads nothing but the reply file's path from the job
          val job = CdtWorker.Job(
            file = "unit.c",
            fingerprint = "fp",
            replyFile = replyFile.toString,
            cacheDir = replyDir.toString,
            fragments = true,
            settings = null
          )

          CdtWorker.writeReply(job, CdtWorker.Reply("ok", "", Nil, Nil))

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.isRegularFile(replyFile, LinkOption.NOFOLLOW_LINKS) shouldBe true
          read[CdtWorker.Reply](Files.readString(replyFile)).status shouldBe "ok"
      }
  }

  "the worker pool's size" should {

      "keep every worker's heap together within half of the parent's" in {
          val gb = 1024L * 1024 * 1024
          List((2L * gb, 16), (8L * gb, 16), (32L * gb, 64), (1L * gb, 2)).foreach {
              (parentMax, cores) =>
                val (count, heapMb) = CdtWorkerPool.sizing(parentMax, cores)
                count should be >= 1
                count should be <= 4
                heapMb should be >= 512L
                heapMb should be <= 4096L
                // the floor of half a gigabyte per worker is the only way past half the heap
                (count * heapMb) should be <= math.max(512L, parentMax / 2 / (1024 * 1024))
          }
      }

      "take the count and heap the system properties give" in {
          System.setProperty(CdtWorkerPool.CountProperty, "3")
          System.setProperty(CdtWorkerPool.HeapMbProperty, "700")
          try CdtWorkerPool.sizing(8L * 1024 * 1024 * 1024, 16) shouldBe (3, 700L)
          finally
            System.clearProperty(CdtWorkerPool.CountProperty)
            System.clearProperty(CdtWorkerPool.HeapMbProperty)
      }
  }

  "the default run" should {

      "keep every unit in the graph, in the process, with the cache" in {
          File.usingTemporaryDirectory("c2worker-default") { root =>
            copyFixture(fixtureDir)(root)
            val (cpg, records, _) = build(root, isolate = false, failure = None, report = true)
            try
              (survivingFunctions ++ failedFunctions).foreach(name =>
                  cpg.method.nameExact(name).l should not be empty
              )
              records shouldBe empty
            finally cpg.close()
          }
      }

      "keep every unit in the graph, in the process, without the cache" in {
          File.usingTemporaryDirectory("c2worker-nocache") { root =>
            copyFixture(fixtureDir)(root)
            val (cpg, records, _) =
                build(root, isolate = false, failure = None, report = true, astCache = false)
            try
              (survivingFunctions ++ failedFunctions).foreach(name =>
                  cpg.method.nameExact(name).l should not be empty
              )
              records shouldBe empty
            finally cpg.close()
          }
      }
  }

  "the parse report of an isolated run" should {

      "carry what a worker's parse reports, its preprocessor problem included" in {
          File.usingTemporaryDirectory("c2worker-report") { root =>
            copyFixture(problemFixtureDir)(root)
            val (cpg, records, _) = build(root, isolate = true, failure = None, report = true)
            try
              // the unit with the include that resolves to nothing is partly read, in the
              // graph, and its parse's own record crossed the worker boundary to the report
              cpg.method.nameExact("held_open").l should not be empty
              cpg.method.nameExact("plain_count").l should not be empty
              val reported = failureRecordsFor(records, "unresolved-include.c")
              reported should not be empty
              reported.foreach { record =>
                record.outcome shouldBe ParseReporter.Outcome.Partial
                record.message should include("preprocessor")
              }
            finally cpg.close()
          }
      }
  }

  "the isolated run over a compilation database" should {

      /** The definition the database's command passes selects the bodies of both functions: what
        * the unit's per-file flags must reach the worker for.
        */
      val definedBody = """static int amount(void)
          |{
          |#ifdef FAST_PATH
          |    return 2;
          |#else
          |    return 5;
          |#endif
          |}
          |
          |int total(void)
          |{
          |#ifdef FAST_PATH
          |    return amount() + 1;
          |#else
          |    return amount() + 100;
          |#endif
          |}""".stripMargin

      val database =
          """[{"directory": ".", "file": "defined-body.c", "command": "cc -DFAST_PATH -c defined-body.c"}]"""

      def prepare(root: File): Unit =
        (root / "defined-body.c").write(definedBody)
        (root / "compile_commands.json").write(database)

      "build the same graph as the in-process run, the entry's flags included" in {
          File.usingTemporaryDirectory("c2worker-db-plain") { plainRoot =>
              File.usingTemporaryDirectory("c2worker-db-isolated") { isolatedRoot =>
                prepare(plainRoot)
                prepare(isolatedRoot)
                val (plain, _, _) = build(
                  plainRoot,
                  isolate = false,
                  failure = None,
                  report = false,
                  compileCommands = Some(plainRoot.pathAsString)
                )
                val (isolated, _, _) = build(
                  isolatedRoot,
                  isolate = true,
                  failure = None,
                  report = false,
                  compileCommands = Some(isolatedRoot.pathAsString)
                )
                try
                  List(plain, isolated).foreach { cpg =>
                    cpg.method.nameExact("total").ast.isLiteral.code.l.sorted shouldBe List("1")
                    cpg.method.nameExact("amount").ast.isLiteral.code.l.sorted shouldBe List("2")
                  }
                  shapeOf(plain) shouldBe shapeOf(isolated)
                  methodFullNames(plain) shouldBe methodFullNames(isolated)
                finally
                  plain.close()
                  isolated.close()
              }
          }
      }
  }
end CdtWorkerTests
