package io.appthreat.edg2atom.passes

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{CompileCommand, CompileDatabase}
import io.appthreat.c2cpg.passes.BuildContextPass
import io.appthreat.edg2atom.Edg2Atom
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Paths
import scala.jdk.CollectionConverters.*
import scala.util.Try

/** The copies the build contexts of a file contribute in this frontend: with `--c-build-contexts
  * all`, a file the compilation database compiles with more than one distinct context is exported
  * once per context, and a function whose body differs across the contexts is kept once per
  * context, the first context's copy under today's full name, every later copy's full name carrying
  * `@ctx:` and the first eight hex digits of its context's fingerprint. A function whose body
  * matches in every context is kept once. A call inside a context reaches that context's copy.
  * Without the option the graph is the one the first entry alone builds, exactly as before.
  */
class EdgBuildContextCopiesTests extends AnyWordSpec with Matchers:

  private val duplicateDir = File(
    Paths.get(getClass.getClassLoader.getResource("contexts/duplicate-entry/selected-body.c").toURI)
  ).parent

  private val targetsDir = File(
    Paths.get(getClass.getClassLoader.getResource("contexts/two-targets/target-scale.c").toURI)
  ).parent

  private def database(entries: String*): String = entries.mkString("[", ",", "]")

  private def entry(file: String, command: String): String =
      s"""{"directory": ".", "file": "$file", "command": "$command"}"""

  private val duplicateDatabase =
      database(
        entry("selected-body.c", "cc -DFAST_PATH -c selected-body.c"),
        entry("selected-body.c", "cc -c selected-body.c")
      )

  private val singleDatabase =
      database(entry("selected-body.c", "cc -DFAST_PATH -c selected-body.c"))

  private val targetsDatabase =
      database(
        entry("target-scale.c", "cc -DTARGET_WIDE -c target-scale.c"),
        entry("target-scale.c", "cc -DTARGET_NARROW -c target-scale.c")
      )

  private def graph(
    fixtureDir: File,
    file: String,
    database: String,
    buildContexts: String
  )(check: Cpg => Unit): Unit =
      File.usingTemporaryDirectory("edgbctxcopies") { root =>
        (root / file).write((fixtureDir / file).contentAsString)
        (root / CompileDatabase.FileName).write(database)
        val out = File.newTemporaryFile("edgbctxcopies", ".bin")
        out.deleteOnExit()
        val cpg = new Edg2Atom().createCpg(
          Config()
              .withInputPath(root.pathAsString)
              .withOutputPath(out.pathAsString)
              .withCompileCommands(root.pathAsString)
              .withFunctionBodies(true)
              .withBuildContexts(buildContexts)
        ).get
        try check(cpg)
        finally cpg.close()
      }

  /** The fingerprint a command line gives, read the way a database entry's command is read. */
  private def fingerprintOf(command: String): String =
      BuildContextPass.fingerprintOf(
        CompileCommand.parseArguments(CompileCommand.tokenize(command), Paths.get(".")),
        Paths.get(".").toAbsolutePath.normalize
      )

  private def copySuffix(command: String): String =
      "@ctx:" + fingerprintOf(command).take(8)

  private def tagsOf(cpg: Cpg, fullName: String): List[String] =
      cpg.method.fullNameExact(fullName).tag.nameExact(X2CpgDefines.BuildContextTag).value.l

  private def calleesOf(cpg: Cpg, methodFullName: String): List[String] =
      cpg.method.fullNameExact(methodFullName).ast.isCall.methodFullName.l
          .filterNot(_.startsWith("<operator>"))
          .distinct
          .sorted

  private def plainAndCopies(cpg: Cpg, name: String): (String, List[String]) =
    val all   = cpg.method.nameExact(name).fullName.l.sorted
    val plain = all.filterNot(_.contains("@ctx"))
    plain should have size 1
    (plain.head, all.filter(_.contains("@ctx")))

  /** The graph's nodes by label and edges by type, without the tags: two graphs are the same graph
    * when this is equal.
    */
  private def shapeOf(cpg: Cpg): (Map[String, Int], Map[String, Int]) =
    val nodes  = cpg.graph.nodes().asScala.toSeq
    val out    = nodes.flatMap(n => Try(n.outE().asScala.toSeq).getOrElse(Nil))
    val labels = nodes.groupBy(_.label()).view.mapValues(_.size).toMap - "TAG"
    val edges  = out.groupBy(_.label()).view.mapValues(_.size).toMap - "TAGGED_BY"
    (labels, edges)

  private def shapeOfFixture(
    fixtureDir: File,
    file: String,
    database: String,
    buildContexts: String
  ): (Map[String, Int], Map[String, Int]) =
    var shape: (Map[String, Int], Map[String, Int]) = (Map.empty, Map.empty)
    graph(fixtureDir, file, database, buildContexts)(cpg => shape = shapeOf(cpg))
    shape

  "the duplicated file, with all" should {

      "keep both bodies of the functions whose bodies differ, under distinct full names" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          val slow = copySuffix("cc -c selected-body.c")
          graph(duplicateDir, "selected-body.c", duplicateDatabase, "all") { cpg =>
            val (total, totalCopies)   = plainAndCopies(cpg, "total")
            val (amount, amountCopies) = plainAndCopies(cpg, "amount")
            totalCopies shouldBe List(s"total$slow")
            amountCopies shouldBe List(s"amount$slow")
            cpg.method.fullNameExact(total).ast.isLiteral.code.l should contain("1")
            cpg.method.fullNameExact(s"total$slow").ast.isLiteral.code.l should contain("100")
            cpg.method.fullNameExact(amount).ast.isLiteral.code.l should contain("2")
            cpg.method.fullNameExact(s"amount$slow").ast.isLiteral.code.l should contain("5")
          }
      }

      "tag the context's copies with their build context, and no other method" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          val slow = copySuffix("cc -c selected-body.c")
          graph(duplicateDir, "selected-body.c", duplicateDatabase, "all") { cpg =>
            val (total, _)  = plainAndCopies(cpg, "total")
            val (amount, _) = plainAndCopies(cpg, "amount")
            tagsOf(cpg, s"total$slow") shouldBe List(fingerprintOf("cc -c selected-body.c"))
            tagsOf(cpg, s"amount$slow") shouldBe List(fingerprintOf("cc -c selected-body.c"))
            tagsOf(cpg, total) shouldBe empty
            tagsOf(cpg, amount) shouldBe empty
          }
      }

      "link each context's caller to the helper copy of its own context" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          val slow = copySuffix("cc -c selected-body.c")
          graph(duplicateDir, "selected-body.c", duplicateDatabase, "all") { cpg =>
            val (total, _)  = plainAndCopies(cpg, "total")
            val (amount, _) = plainAndCopies(cpg, "amount")
            calleesOf(cpg, total) shouldBe List(amount)
            calleesOf(cpg, s"total$slow") shouldBe List(s"amount$slow")
          }
      }
  }

  "the two-target file, with all" should {

      "keep the target's copy of the function whose body differs and the shared one once" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          val narrow = copySuffix("cc -DTARGET_NARROW -c target-scale.c")
          graph(targetsDir, "target-scale.c", targetsDatabase, "all") { cpg =>
            val (scale, scaleCopies) = plainAndCopies(cpg, "scale")
            scaleCopies shouldBe List(s"scale$narrow")
            cpg.method.fullNameExact(scale).ast.isLiteral.code.l should contain("2")
            cpg.method.fullNameExact(s"scale$narrow").ast.isLiteral.code.l should contain("4")
            cpg.method.nameExact("limit").l should have size 1
            (cpg.method.nameExact("limit").fullName.l.head should not).include("@ctx")
          }
      }
  }

  /** A graph of the project `files` spell, with the given setting. Cancels the test where edga is
    * not installed, as every other test here does.
    */
  private def projectGraph(files: Map[String, String], buildContexts: String)(
    check: Cpg => Unit
  ): Unit =
    assume(EdgaRunner.locate().isDefined, "edga is not installed")
    File.usingTemporaryDirectory("edgbctxproject") { root =>
      files.foreach((name, text) => (root / name).write(text))
      val out = File.newTemporaryFile("edgbctxproject", ".bin")
      out.deleteOnExit()
      val cpg = new Edg2Atom().createCpg(
        Config()
            .withInputPath(root.pathAsString)
            .withOutputPath(out.pathAsString)
            .withCompileCommands(root.pathAsString)
            .withFunctionBodies(true)
            .withBuildContexts(buildContexts)
      ).get
      try check(cpg)
      finally cpg.close()
    }

  "a function defined in both arms of a conditional, with all" should {

      "keep one copy per context, a shared body once, and give the caller its context's copy" in {
          val files = Map(
            "arms.c" ->
                """#ifdef WIDE
                  |int pick(void) { return 1; }
                  |#else
                  |int pick(void)
                  |{
                  |  return 2;
                  |}
                  |#endif
                  |#ifdef WIDE
                  |int same(void) { return 7; }
                  |#else
                  |int same(void) { return 7; }
                  |#endif
                  |int use_pick(void) { return pick() + same(); }
                  |""".stripMargin,
            CompileDatabase.FileName -> database(
              entry("arms.c", "cc -DWIDE -c arms.c"),
              entry("arms.c", "cc -c arms.c")
            )
          )
          projectGraph(files, "all") { cpg =>
            val narrow             = copySuffix("cc -c arms.c")
            val (pick, pickCopies) = plainAndCopies(cpg, "pick")
            pickCopies shouldBe List(s"pick$narrow")
            cpg.method.nameExact("same").l should have size 1
            val (same, _)        = plainAndCopies(cpg, "same")
            val (usePick, users) = plainAndCopies(cpg, "use_pick")
            users shouldBe List(s"use_pick$narrow")
            calleesOf(cpg, usePick) shouldBe List(pick, same).sorted
            calleesOf(cpg, s"use_pick$narrow") shouldBe List(s"pick$narrow", same).sorted
          }
      }

      "rename only the copy of the file whose body differs" in {
          val files = Map(
            "a.c" -> "static int helper(void) { return 3; }\nint a_entry(void) { return helper(); }\n",
            "b.c" -> "#ifdef WIDE\nstatic int helper(void) { return 30; }\n#else\nstatic int helper(void) { return 40; }\n#endif\nint b_entry(void) { return helper(); }\n",
            CompileDatabase.FileName -> database(
              entry("a.c", "cc -DWIDE -c a.c"),
              entry("a.c", "cc -c a.c"),
              entry("b.c", "cc -DWIDE -c b.c"),
              entry("b.c", "cc -c b.c")
            )
          )
          projectGraph(files, "all") { cpg =>
            cpg.method.nameExact("helper").filenameExact("a.c").l should have size 1
            cpg.method.nameExact("helper").filenameExact("a.c").fullName.l.exists(
              _.contains("@ctx")
            ) shouldBe false
            cpg.method.nameExact("helper").filenameExact("b.c").fullName.l.count(
              _.contains("@ctx")
            ) shouldBe 1
          }
      }

      "keep the context's copy of a function a header the unit owns defines" in {
          val files = Map(
            "u.c" -> "#include \"h.h\"\nint u_entry(void) { return hv(); }\n",
            "h.h" -> "#ifndef H_H\n#define H_H\nstatic inline int hv(void) {\n#ifdef WIDE\n  return 1;\n#else\n  return 2;\n#endif\n}\n#endif\n",
            CompileDatabase.FileName -> database(
              entry("u.c", "cc -DWIDE -c u.c"),
              entry("u.c", "cc -c u.c")
            )
          )
          projectGraph(files, "all") { cpg =>
            val hvs = cpg.method.nameExact("hv").l
            hvs.map(_.ast.isLiteral.code.l.toSet).toSet shouldBe Set(Set("1"), Set("2"))
            hvs.count(_.fullName.contains("@ctx")) shouldBe 1
          }
      }
  }

  "the default setting" should {

      "build the graph the first entry alone builds, exactly as before" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          shapeOfFixture(duplicateDir, "selected-body.c", duplicateDatabase, "first") shouldBe
              shapeOfFixture(duplicateDir, "selected-body.c", singleDatabase, "first")
      }

      "give a look-alike project with no duplicates the same graph under all" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          shapeOfFixture(duplicateDir, "selected-body.c", singleDatabase, "all") shouldBe
              shapeOfFixture(duplicateDir, "selected-body.c", singleDatabase, "first")
      }
  }
end EdgBuildContextCopiesTests
