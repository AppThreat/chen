package io.appthreat.jimple2cpg

import better.files.File
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.sys.process.*

/** chen#255: an exception while a class's AST is built was swallowed whole, not even logged. A
  * class file whose bytecode survives enumeration but not soot's loader now records as dropped,
  * next to its good twin that stays in the graph.
  */
class ParseFailureReportingTests extends AnyWordSpec with Matchers:

  private def withReporterEnabled[T](body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    ParseReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      ParseReporter.reset()

  /** Compiles a good twin and two bad ones and returns the classes directory. One bad file has its
    * bytecode scrambled past what the package-path reader tolerates, so it is dropped at
    * extraction; the other extends a class that is deleted after compilation, so soot refuses to
    * load it in the AST pass.
    */
  private def buildProject(): File =
    val dir = File.newTemporaryDirectory("jimple-parse-report")
    val src = (dir / "src").createDirectoryIfNotExists()
    (src / "Good.java").writeText(
      "public class Good {\n  public int add(int a, int b) { return a + b; }\n}\n"
    )
    (src / "Scrambled.java").writeText(
      "public class Scrambled {\n  public int twice(int x) { return x * 2; }\n}\n"
    )
    (src / "MissingBase.java").writeText("public class MissingBase {\n}\n")
    (src / "NoSuper.java").writeText(
      "public class NoSuper extends MissingBase {\n  public int thrice(int x) { return x * 3; }\n}\n"
    )
    val classes = (dir / "classes").createDirectoryIfNotExists()
    Seq(
      "javac",
      "-g",
      "-d",
      classes.toString,
      (src / "Good.java").toString,
      (src / "Scrambled.java").toString,
      (src / "MissingBase.java").toString,
      (src / "NoSuper.java").toString
    ).!!
    val scrambled = classes / "Scrambled.class"
    val bytes     = scrambled.bytes.toArray
    for i <- (bytes.length / 2) until (bytes.length / 2 + 24) do bytes(i) = (0x5a).toByte
    scrambled.outputStream.foreach(_.write(bytes))
    (classes / "MissingBase.class").delete()
    classes
  end buildProject

  private def buildCpg(classes: File): Cpg =
    val config = Config().withInputPath(classes.toString).withOutputPath(
      File.newTemporaryDirectory("jimple-parse-report-out").toString
    )
    new Jimple2Cpg().createCpg(config).get

  "jimple2cpg parse failure reporting" should {

      "record the classes dropped at extraction and in the AST pass, and not their good twin" in
          withReporterEnabled {
              val classes = buildProject()
              val cpg     = buildCpg(classes)
              try
                val scrambled = ParseReporter.records.filter(_.file == "Scrambled.class")
                scrambled should have size 1
                scrambled.head.frontend shouldBe "jimple"
                scrambled.head.outcome shouldBe "unparsed"
                scrambled.head.stage shouldBe "parse"
                scrambled.head.message should startWith(
                  "the package path could not be read from the bytecode:"
                )

                val noSuper = ParseReporter.records.filter(_.file.endsWith("NoSuper.class"))
                noSuper shouldBe empty // soot's phantom classes rescue a missing superclass

                // the good twin is in the graph, unchanged, and the scrambled one is not
                cpg.method.name("add").l should have size 1
                cpg.method.name("twice").l shouldBe empty
              finally cpg.close()
          }

      "record a class the AST pass cannot load, at the ast stage" in withReporterEnabled {
          // soot rescues a missing superclass with a phantom class, so the pass-level catch is
          // driven with a class file whose name resolves to nothing on the classpath.
          val classes = (File.newTemporaryDirectory("jimple-parse-report-ast") / "Nothing.class")
          classes.outputStream.foreach(
            _.write(Array(0xca.toByte, 0xfe.toByte, 0xba.toByte, 0xbe.toByte))
          )
          val classFile = io.appthreat.jimple2cpg.util.ProgramHandlingUtil.ClassFile(
            classes,
            Some("nonexistent/Nothing"),
            None
          )
          val config = Config().withInputPath(classes.parent.toString).withOutputPath(
            File.newTemporaryDirectory("jimple-parse-report-ast-out").toString
          )
          val cpg = io.appthreat.x2cpg.X2Cpg.newEmptyCpg()
          // the frontend's own soot configuration allows phantom classes, which rescue a
          // missing name; without them the load throws, the way a broken class does in a run
          // whose classpath cannot resolve it
          soot.options.Options.v().set_allow_phantom_refs(false)
          new io.appthreat.jimple2cpg.passes.AstCreationPass(List(classFile), cpg, config)
              .createAndApply()
          soot.options.Options.v().set_allow_phantom_refs(true)
          cpg.close()
          ParseReporter.records.filter(_.file == "Nothing.class") should have size 1
          ParseReporter.records.head.frontend shouldBe "jimple"
          ParseReporter.records.head.outcome shouldBe "dropped"
          ParseReporter.records.head.stage shouldBe "ast"
          ParseReporter.records.head.message should startWith("SootClassNotFoundException:")
      }

      "record nothing when the reporter is disabled" in {
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          val classes = buildProject()
          val cpg     = buildCpg(classes)
          try ParseReporter.records shouldBe empty
          finally cpg.close()
      }
  }
end ParseFailureReportingTests
