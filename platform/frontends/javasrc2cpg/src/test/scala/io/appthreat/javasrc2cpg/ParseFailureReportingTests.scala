package io.appthreat.javasrc2cpg

import com.github.javaparser.StaticJavaParser
import com.github.javaparser.ast.Node
import com.github.javaparser.symbolsolver.JavaSymbolSolver
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver
import io.appthreat.javasrc2cpg.passes.AstCreator
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.datastructures.Global
import io.appthreat.x2cpg.parse.{ParseFailureRecord, ParseReporter}
import io.appthreat.x2cpg.testfixtures.LogCapture
import org.apache.logging.log4j.Level
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.collection.mutable

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** chen#255: a file javasrc2cpg cannot parse must be recorded, its good twin must not, and the
  * default log must stay quiet about both.
  */
class ParseFailureReportingTests extends AnyWordSpec with Matchers:

  private def buildProject(): Path =
    val root = Files.createTempDirectory("javasrc-parse-report")
    val src  = Files.createDirectories(root.resolve("src/main/java/pkg"))
    Files.writeString(
      src.resolve("Good.java"),
      """package pkg;
            |public class Good {
            |    public int add(int a, int b) { return a + b; }
            |}
            |""".stripMargin
    )
    Files.writeString(src.resolve("Broken.java"), "class Broken {{{\n")
    root

  private def buildCpg(root: Path, output: Path): Cpg =
    val config = JavaSrc2Cpg.DefaultConfig
        .withInputPath(root.toString)
        .withOutputPath(output.toString)
    val cpg = new JavaSrc2Cpg().createCpg(config).get
    // the file nodes come from the default overlays, as in JavaSrcTestCpg.applyPasses
    X2Cpg.applyDefaultOverlays(cpg)
    cpg

  private def withReporterEnabled[T](body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    ParseReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      ParseReporter.reset()

  "javasrc2cpg parse failure reporting" should {

      "record the file JavaParser cannot parse and not its good twin" in withReporterEnabled {
          val root = Files.createTempDirectory("javasrc-parse-report-out")
          val cpg  = buildCpg(buildProject(), root.resolve("cpg.bin"))
          try
            val broken = ParseReporter.records.filter(_.file.endsWith("Broken.java"))
            broken should have size 1
            broken.head.frontend shouldBe "javasrc"
            broken.head.outcome shouldBe "unparsed"
            broken.head.stage shouldBe "parse"
            // JavaParser's own error text for this construct
            broken.head.message should startWith("Parse error. Found \"{\", expected \"}\"")
            broken.head.file shouldBe "src/main/java/pkg/Broken.java"
            ParseReporter.records.exists(_.file.endsWith("Good.java")) shouldBe false

            // the good twin is in the graph, unchanged, and the broken one is not
            cpg.file.name.l.exists(_.endsWith("pkg/Good.java")) shouldBe true
            cpg.file.name.l.exists(_.endsWith("pkg/Broken.java")) shouldBe false
            cpg.method.name("add").l should have size 1
          finally cpg.close()
      }

      "record nothing when the reporter is disabled" in {
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          val out = Files.createTempDirectory("javasrc-parse-report-off")
          val cpg = buildCpg(buildProject(), out.resolve("cpg.bin"))
          try ParseReporter.records shouldBe empty
          finally cpg.close()
      }

      "record a file whose AST creation throws, with the exception's class and message" in withReporterEnabled {
          // No known Java source makes the JVM-side AstCreator throw today (the Lombok crashes
          // were native-image reflection misses), so the failure is injected where the creator
          // consults positions: the catch under test is the one that runs when anything in
          // astForTranslationUnit throws.
          val compilationUnit = StaticJavaParser.parse(
            """public class A {
                |    int f;
                |    void m() { int x = 1; }
                |}
                |""".stripMargin
          )
          val creator = new AstCreator(
            "A.java",
            compilationUnit,
            new Global(),
            new JavaSymbolSolver(new ReflectionTypeSolver()),
            mutable.HashMap.empty[String, mutable.Set[String]]
          )(using ValidationMode.Disabled):
            override protected def line(node: Node): Option[Integer] =
                throw new IllegalStateException("injected AST failure")
          creator.createAst()
          ParseReporter.records shouldBe List(
            ParseFailureRecord(
              "javasrc",
              "A.java",
              "dropped",
              "ast",
              "IllegalStateException: injected AST failure"
            )
          )
      }

      "log nothing for the lost file at the default level and the reason at debug" in withReporterEnabled {
          // The logger SourceParser uses; log4j2's default root level is what a default run gets.
          val defaultOut = LogCapture.withCapture(
            classOf[io.appthreat.javasrc2cpg.util.SourceParser].getName,
            Level.WARN
          ) { appender =>
            val out = Files.createTempDirectory("javasrc-parse-report-quiet")
            val cpg = buildCpg(buildProject(), out.resolve("cpg.bin"))
            cpg.close()
            appender.messagesAtOrAbove(Level.WARN)
          }
          defaultOut.exists(message => message.contains("Broken.java")) shouldBe false

          val debugOut = LogCapture.withCapture(
            classOf[io.appthreat.javasrc2cpg.util.SourceParser].getName,
            Level.DEBUG
          ) { appender =>
            val out = Files.createTempDirectory("javasrc-parse-report-debug")
            val cpg = buildCpg(buildProject(), out.resolve("cpg.bin"))
            cpg.close()
            appender.messagesAt(Level.DEBUG)
          }
          debugOut.exists(message =>
              message.contains("Broken.java") && message.contains("Unable to parse")
          ) shouldBe true
          debugOut.exists(message => message.contains("Good.java")) shouldBe false
      }
  }
end ParseFailureReportingTests
