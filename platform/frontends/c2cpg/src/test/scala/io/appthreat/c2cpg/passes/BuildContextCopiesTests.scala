package io.appthreat.c2cpg.passes

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.{CompileCommand, FileDefaults}
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.testfixtures.DefaultTestCpg
import io.shiftleft.semanticcpg.language.*

import java.nio.file.Paths
import scala.jdk.CollectionConverters.*

/** The copies a file's build contexts contribute: with `--c-build-contexts all`, a file the
  * compilation database compiles with more than one distinct context is analysed once per context.
  * A function whose body is the same in every context is kept once, the copy the first context
  * wrote; a function whose body differs is kept once per context, the first context's copy under
  * today's full name and every other copy's full name carrying `@ctx:` and the first eight hex
  * digits of its context's fingerprint, with the context on a `build-context` tag. A call inside a
  * context reaches that context's copy. Without the option the graph is the one the first entry
  * alone builds, exactly as before.
  */
class BuildContextCopiesTests extends CCodeToCpgSuite(FileDefaults.C_EXT):

  private val duplicateDir = File(
    Paths.get(getClass.getClassLoader.getResource("contexts/duplicate-entry/selected-body.c").toURI)
  ).parent

  private val targetsDir = File(
    Paths.get(getClass.getClassLoader.getResource("contexts/two-targets/target-scale.c").toURI)
  ).parent

  private def sourceOf(dir: File, name: String): String = (dir / name).contentAsString

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

  private def fixture(file: String, source: String, db: String, buildContexts: String) =
      code(source, file)
          .moreCode(db, "compile_commands.json")
          .withConfig(
            Config().withCompileCommands("compile_commands.json").withBuildContexts(buildContexts)
          )

  /** The duplicated-file fixture: both functions' bodies are selected by the definition, and the
    * caller reaches the helper it calls in its own context.
    */
  private val duplicateSource = sourceOf(duplicateDir, "selected-body.c")

  private val duplicateAll = fixture("selected-body.c", duplicateSource, duplicateDatabase, "all")
  private val duplicateFirst =
      fixture("selected-body.c", duplicateSource, duplicateDatabase, "first")
  private val duplicateSingle = fixture("selected-body.c", duplicateSource, singleDatabase, "first")
  private val lookalikeAll    = fixture("selected-body.c", duplicateSource, singleDatabase, "all")

  /** The two-target fixture: the two build contexts compile different bodies of scale and the same
    * body of limit.
    */
  private val targetsSource = sourceOf(targetsDir, "target-scale.c")

  private val targetsAll = fixture("target-scale.c", targetsSource, targetsDatabase, "all")

  /** The fingerprint a command line gives, read the way a database entry's command is read. */
  private def fingerprintOf(command: String): String =
      BuildContextPass.fingerprintOf(
        CompileCommand.parseArguments(CompileCommand.tokenize(command), Paths.get(".")),
        Paths.get(".").toAbsolutePath.normalize
      )

  private def copySuffix(command: String): String =
      "@ctx:" + fingerprintOf(command).take(8)

  private def tagsOf(cpg: DefaultTestCpg, fullName: String): List[String] =
      cpg.method.fullNameExact(fullName).tag.nameExact(X2CpgDefines.BuildContextTag).value.l

  /** The full names of the functions one method's body calls, what a call is linked by. */
  private def calleesOf(cpg: DefaultTestCpg, methodFullName: String): List[String] =
      cpg.method.fullNameExact(methodFullName).ast.isCall.methodFullName.l
          .filterNot(_.startsWith("<operator>"))
          .distinct
          .sorted

  /** The graph's nodes by label and edges by type, without the tags: two graphs are the same graph
    * when this is equal.
    */
  private def shapeOf(cpg: DefaultTestCpg): (Map[String, Int], Map[String, Int]) =
    val nodes  = cpg.graph.nodes().asScala.toSeq
    val out    = nodes.flatMap(n => n.outE().asScala.toSeq)
    val labels = nodes.groupBy(_.label()).view.mapValues(_.size).toMap - "TAG"
    val edges  = out.groupBy(_.label()).view.mapValues(_.size).toMap - "TAGGED_BY"
    (labels, edges)

  private def buildContextTagsOf(cpg: DefaultTestCpg): List[String] =
      cpg.tag.nameExact(X2CpgDefines.BuildContextTag).value.l.sorted

  /** The context's plain full name and the full names of its copies, one per later context. */
  private def plainAndCopies(cpg: DefaultTestCpg, name: String): (String, List[String]) =
    val all   = cpg.method.nameExact(name).fullName.l.sorted
    val plain = all.filterNot(_.contains("@ctx"))
    plain should have size 1
    (plain.head, all.filter(_.contains("@ctx")))

  "a file compiled for two contexts, with all" should {

      "keep both bodies of the functions whose bodies differ, under distinct full names" in {
          val slow                   = copySuffix("cc -c selected-body.c")
          val (total, totalCopies)   = plainAndCopies(duplicateAll, "total")
          val (amount, amountCopies) = plainAndCopies(duplicateAll, "amount")
          totalCopies shouldBe List(s"total$slow")
          amountCopies shouldBe List(s"amount$slow")
          // the bodies are the ones each context compiles: the fast path in today's copies
          duplicateAll.method.fullNameExact(total).code.l.head should include("1")
          duplicateAll.method.fullNameExact(s"total$slow").code.l.head should include("100")
          duplicateAll.method.fullNameExact(amount).code.l.head should include("2")
          duplicateAll.method.fullNameExact(s"amount$slow").code.l.head should include("5")
      }

      "tag the context's copies with their build context, and no other method" in {
          val slow                   = copySuffix("cc -c selected-body.c")
          val (total, totalCopies)   = plainAndCopies(duplicateAll, "total")
          val (amount, amountCopies) = plainAndCopies(duplicateAll, "amount")
          tagsOf(duplicateAll, s"total$slow") shouldBe
              List(fingerprintOf("cc -c selected-body.c"))
          tagsOf(duplicateAll, s"amount$slow") shouldBe
              List(fingerprintOf("cc -c selected-body.c"))
          // today's copies, which keep today's full names, carry no build-context tag
          tagsOf(duplicateAll, total) shouldBe empty
          tagsOf(duplicateAll, amount) shouldBe empty
      }

      "link each context's caller to the helper copy of its own context" in {
          val slow        = copySuffix("cc -c selected-body.c")
          val (total, _)  = plainAndCopies(duplicateAll, "total")
          val (amount, _) = plainAndCopies(duplicateAll, "amount")
          calleesOf(duplicateAll, total) shouldBe List(amount)
          calleesOf(duplicateAll, s"total$slow") shouldBe List(s"amount$slow")
      }
  }

  "a file built for two targets, with all" should {

      "keep the target's copy of the function whose body differs" in {
          val narrow               = copySuffix("cc -DTARGET_NARROW -c target-scale.c")
          val (scale, scaleCopies) = plainAndCopies(targetsAll, "scale")
          scaleCopies shouldBe List(s"scale$narrow")
          // the wide target's factor is in today's copy, the narrow one's in the copy
          targetsAll.method.fullNameExact(scale).ast.isLiteral.code.l should contain("2")
          targetsAll.method.fullNameExact(s"scale$narrow").ast.isLiteral.code.l should contain("4")
      }

      "keep the function whose body matches in every context exactly once" in {
          targetsAll.method.nameExact("limit").l should have size 1
          (targetsAll.method.nameExact("limit").fullName.l.head should not).include("@ctx")
          targetsAll.method.fullName(".*@ctx.*").name.l should not contain "limit"
      }
  }

  /** Two definitions in the two arms of a conditional sit on different lines: they are the copies
    * of one function all the same, and a caller whose text is the same in both contexts still
    * reaches its own context's copy.
    */
  private val armsSource =
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
        |""".stripMargin

  private val armsAll =
      fixture(
        "arms.c",
        armsSource,
        database(entry("arms.c", "cc -DWIDE -c arms.c"), entry("arms.c", "cc -c arms.c")),
        "all"
      )

  "a function defined in both arms of a conditional, with all" should {

      "keep one copy per context and rename the later context's" in {
          val narrow             = copySuffix("cc -c arms.c")
          val (pick, pickCopies) = plainAndCopies(armsAll, "pick")
          pickCopies shouldBe List(s"pick$narrow")
          armsAll.method.fullNameExact(pick).ast.isLiteral.code.l should contain("1")
          armsAll.method.fullNameExact(s"pick$narrow").ast.isLiteral.code.l should contain("2")
          tagsOf(armsAll, s"pick$narrow") shouldBe List(fingerprintOf("cc -c arms.c"))
      }

      "keep a definition whose body is the same in both arms once" in {
          armsAll.method.nameExact("same").fullName.l should have size 1
      }

      "give a caller whose text is the same in both contexts a copy that reaches its context's callee" in {
          val narrow                   = copySuffix("cc -c arms.c")
          val (usePick, usePickCopies) = plainAndCopies(armsAll, "use_pick")
          usePickCopies shouldBe List(s"use_pick$narrow")
          val (pick, _) = plainAndCopies(armsAll, "pick")
          val (same, _) = plainAndCopies(armsAll, "same")
          calleesOf(armsAll, usePick) shouldBe List(pick, same).sorted
          calleesOf(armsAll, s"use_pick$narrow") shouldBe List(s"pick$narrow", same).sorted
      }

      "leave no two methods of the file under one full name" in {
          val names = armsAll.method.filenameExact("arms.c").filterNot(_.name == "<global>")
              .fullName.l
          names.distinct.size shouldBe names.size
      }
  }

  /** Two files with a static function of the same name: only the one whose body differs by context
    * gets a copy.
    */
  private val staticAll =
      code("static int helper(void) { return 3; }\nint a_entry(void) { return helper(); }\n", "a.c")
          .moreCode(
            "#ifdef WIDE\nstatic int helper(void) { return 30; }\n#else\nstatic int helper(void) { return 40; }\n#endif\nint b_entry(void) { return helper(); }\n",
            "b.c"
          )
          .moreCode(
            database(
              entry("a.c", "cc -DWIDE -c a.c"),
              entry("a.c", "cc -c a.c"),
              entry("b.c", "cc -DWIDE -c b.c"),
              entry("b.c", "cc -c b.c")
            ),
            "compile_commands.json"
          )
          .withConfig(
            Config().withCompileCommands("compile_commands.json").withBuildContexts("all")
          )

  "static functions of one name in two files, with all" should {

      "rename only the copy of the file whose body differs" in {
          staticAll.method.nameExact("helper").filenameExact("a.c").fullName.l.filter(
            _.contains("@ctx")
          ) shouldBe empty
          staticAll.method.nameExact("helper").filenameExact("a.c").l should have size 1
          staticAll.method.nameExact("helper").filenameExact("b.c").fullName.l.count(
            _.contains("@ctx")
          ) shouldBe 1
          staticAll.method.nameExact("a_entry").l should have size 1
      }
  }

  /** An inline member function whose body differs by context. */
  private val memberAll =
      code(
        """class Box {
          |public:
          |  int size() {
          |#ifdef WIDE
          |    return 1;
          |#else
          |    return 2;
          |#endif
          |  }
          |};
          |int use(Box &b) { return b.size(); }
          |""".stripMargin,
        "box.cpp"
      ).moreCode(
        database(entry("box.cpp", "c++ -DWIDE -c box.cpp"), entry("box.cpp", "c++ -c box.cpp")),
        "compile_commands.json"
      ).withConfig(Config().withCompileCommands("compile_commands.json").withBuildContexts("all"))

  "an inline member function whose body differs by context, with all" should {

      "keep the later context's copy beside the first context's" in {
          val sizes = memberAll.method.nameExact("size").l
          sizes.map(_.ast.isLiteral.code.l.toSet).toSet shouldBe Set(Set("1"), Set("2"))
          sizes.count(_.fullName.contains("@ctx")) shouldBe 1
          // the copy keeps its place in the class: one TYPE_DECL holds both
          memberAll.typeDecl.nameExact("Box").l should have size 1
          memberAll.typeDecl.nameExact("Box").astChildren.isMethod.name.l.count(
            _ == "size"
          ) shouldBe 2
      }
  }

  "the default setting" should {

      "build the graph the first entry alone builds, exactly as before" in {
          // the duplicate database contributes nothing of its second entry: the whole graph,
          // build-context tags included, is the look-alike's
          shapeOf(duplicateFirst) shouldBe shapeOf(duplicateSingle)
          buildContextTagsOf(duplicateFirst) shouldBe buildContextTagsOf(duplicateSingle)
          duplicateFirst.method.nameExact("total").l should have size 1
          duplicateFirst.literal.code.l should not contain "5"
      }

      "give a look-alike project with no duplicates the same graph under all" in {
          shapeOf(lookalikeAll) shouldBe shapeOf(duplicateSingle)
          buildContextTagsOf(lookalikeAll) shouldBe buildContextTagsOf(duplicateSingle)
          lookalikeAll.method.nameExact("total").l should have size 1
      }

      "analyse both contexts of the duplicated file under all" in {
          duplicateAll.method.nameExact("total").l should have size 2
          duplicateAll.literal.code.l.sorted shouldBe List("1", "100", "2", "5")
      }
  }

  "the copies over the AST cache" should {

      /** The full names and the build-context tags of the unit's methods, what the copies change:
        * the extra contexts are analysed fresh on every run, and the run over the cached project
        * must give the copies the fresh parse gave.
        */
      def copiesOf(cpg: io.shiftleft.codepropertygraph.Cpg): Map[String, List[String]] =
          cpg.method.nameExact("total").l.map(m =>
              m.fullName -> m.tag.nameExact(X2CpgDefines.BuildContextTag).value.l
          ).toMap

      def build(root: File): io.shiftleft.codepropertygraph.Cpg =
        val out = File.newTemporaryFile("c2bctxcopies", ".bin")
        out.deleteOnExit()
        new io.appthreat.c2cpg.C2Cpg().createCpg(
          Config()
              .withInputPath(root.pathAsString)
              .withOutputPath(out.pathAsString)
              .withCompileCommands(root.pathAsString)
              .withFunctionBodies(true)
              .withBuildContexts("all")
        ).get

      "be the same on the run over the cached project as on the fresh parse, bitcode cache" in {
          File.usingTemporaryDirectory("c2bctxcopies") { root =>
            (root / "selected-body.c").write(duplicateSource)
            (root / "compile_commands.json").write(duplicateDatabase)
            val cold      = build(root)
            val coldNames = copiesOf(cold)
            cold.close()
            (root / ".chen").glob("*.ast").toList should not be empty
            val warm      = build(root)
            val warmNames = copiesOf(warm)
            warm.close()
            warmNames shouldBe coldNames
          }
      }

      "be the same on the run over the cached project as on the fresh parse, fragments" in {
          io.appthreat.x2cpg.passes.frontend.CacheControl.enableFragments()
          try
              File.usingTemporaryDirectory("c2bctxcopiesfrag") { root =>
                (root / "selected-body.c").write(duplicateSource)
                (root / "compile_commands.json").write(duplicateDatabase)
                val cold      = build(root)
                val coldNames = copiesOf(cold)
                cold.close()
                val warm      = build(root)
                val warmNames = copiesOf(warm)
                warm.close()
                warmNames shouldBe coldNames
              }
          finally io.appthreat.x2cpg.passes.frontend.CacheControl.disableFragments()
      }
  }
end BuildContextCopiesTests
