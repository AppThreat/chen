package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.{DataFlowCodeToCpgSuite, DataFlowTestCpg}
import io.appthreat.x2cpg.passes.taggers.js.{
    JsFrameworkRecognizersPass,
    JsGeneratedFiles,
    JsIndexes,
    JsStats
}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** The per-graph name indexes of the JS taggers. Each one must answer exactly what the graph-wide
  * scan it replaces answers, and the searches built on them must grow linearly with the project:
  * the tests count lookups and candidates examined, never time.
  */
class JsIndexesTest extends DataFlowCodeToCpgSuite:

  /** Two files declaring `helper`, nested functions, a decorated class, and a call nothing
    * resolves.
    */
  private def fixture(): Cpg =
      code(
        """
      |export function helper(x) { return x; }
      |export function outer() {
      |  function inner() { return helper(1); }
      |  return inner();
      |}
      |export class Card { constructor() { this.title = 'a'; } render() { return helper(2); } }
      |""".stripMargin,
        "src/a.js"
      ).moreCode(
        """
      |import { helper as h } from './a';
      |export function helper(y) { return y + 1; }
      |function render() { return helper(3) + h(4) + mystery(5) + window.unknown(6); }
      |export class Card { render() { return 1; } }
      |""".stripMargin,
        "src/b.js"
      ).moreCode(
        """
      |function Input() { return () => {}; }
      |class Panel { @Input() name = 'x'; @Input() other = 'y'; }
      |""".stripMargin,
        "src/panel.ts"
      )

  private def ids(nodes: IterableOnce[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]) =
      nodes.iterator.map(_.id()).toList

  "The name indexes" should {

      "answer every call name exactly as the scan does, in graph order" in {
          val cpg = fixture()
          val g   = cpg.graph
          val all = cpg.call.name.toSet + "no-such-call"
          all.foreach { n =>
              withClue(s"calls named $n: ") {
                  ids(JsIndexes.callsNamed(g, n)) shouldBe ids(cpg.call.nameExact(n).l)
              }
          }
          (all should contain).allOf("helper", "mystery", "unknown")
      }

      "answer every method name exactly as the scans do, with same-named methods in two files" in {
          val cpg = fixture()
          val g   = cpg.graph
          val all = cpg.method.name.toSet + "no-such-method"
          all.foreach { n =>
            withClue(s"methods named $n: ") {
                ids(JsIndexes.methodsByName(g, n)) shouldBe ids(cpg.method.nameExact(n).l)
                ids(JsIndexes.internalMethodsByName(g, n)) shouldBe
                    ids(cpg.method.internal.nameExact(n).l)
            }
            cpg.file.name.l.foreach { f =>
                withClue(s"$n in $f: ") {
                    ids(JsIndexes.methodsInFile(g, f, n)) shouldBe
                        ids(cpg.file.nameExact(f).method.nameExact(n).l)
                }
            }
          }
          cpg.method.nameExact("helper").filename.toSet.size should be >= 2
          // nested functions are methods of their file too
          JsIndexes.methodsInFile(g, "src/a.js", "inner") should have size 1
      }

      "answer methods by file, and type declarations and annotations by name" in {
          val cpg = fixture()
          val g   = cpg.graph
          (cpg.file.name.toSet + "src/none.js").foreach { f =>
              ids(JsIndexes.methodsByFile(g, f)) shouldBe ids(cpg.method.filenameExact(f).l)
          }
          (cpg.typeDecl.fullName.toSet + "no.such.Type").foreach { n =>
              ids(JsIndexes.typeDeclsByFullName(g, n)) shouldBe
                  ids(cpg.typeDecl.fullNameExact(n).l)
          }
          (cpg.annotation.name.toSet + "NoSuchAnnotation").foreach { n =>
              ids(JsIndexes.annotationsNamed(g, n)) shouldBe ids(cpg.annotation.nameExact(n).l)
          }
          cpg.typeDecl.nameExact("Card").fullName.toSet.size shouldBe 2
          JsIndexes.annotationsNamed(g, "Input") should have size 2
      }

      "keep the indexes of two graphs apart" in {
          val one = fixture()
          val two = code("function only() {}", "only.js")
          JsIndexes.callsNamed(one.graph, "helper") should not be empty
          JsIndexes.callsNamed(two.graph, "helper") shouldBe empty
          JsIndexes.methodsByName(two.graph, "only") should have size 1
          JsIndexes.methodsByName(one.graph, "only") shouldBe empty
      }

      "stay exact after the taggers have run, because they add no nodes of these kinds" in {
          val cpg = fixture()
          val g   = cpg.graph
          def shape =
              (
                cpg.call.size,
                cpg.method.size,
                cpg.typeDecl.size,
                cpg.annotation.size,
                cpg.file.size,
                ids(cpg.call.nameExact("helper").l)
              )
          // build every index first, so a tagger that added a node would leave it stale
          JsIndexes.callsNamed(g, "helper")
          JsIndexes.methodsByName(g, "helper")
          val before = shape
          new JsFrameworkRecognizersPass(cpg).createAndApply()
          shape shouldBe before
          ids(JsIndexes.callsNamed(g, "helper")) shouldBe ids(cpg.call.nameExact("helper").l)
          ids(JsIndexes.methodsByName(g, "helper")) shouldBe ids(cpg.method.nameExact("helper").l)
      }
  }

  // ---------------------------------------------------------------------------------------------
  // Generated files
  // ---------------------------------------------------------------------------------------------

  "The generated-file detector" should {

      "never take hand-written sources for generated code" in {
          val handWritten =
              (0 until 200).map(i => s"export function f$i(a, b) { return a + b + $i; }")
                  .mkString("\n")
          handWritten.length should be > JsGeneratedFiles.MinimumSize
          JsGeneratedFiles.looksGenerated(handWritten) shouldBe false
          // a long literal is not a bundle either
          JsGeneratedFiles.looksGenerated("const t = `" + "x" * 5000 + "`;\n" * 30) shouldBe false
          JsGeneratedFiles.looksGenerated("function f() {}") shouldBe false
      }

      "take a minified bundle on a few long lines for generated code" in {
          val minified = (0 until 400).map(i => s"function a$i(e,t){return e+t+$i}").mkString(";")
          minified.length should be > JsGeneratedFiles.MinimumSize
          JsGeneratedFiles.looksGenerated(minified) shouldBe true
          JsGeneratedFiles.looksGenerated(minified + "\n" + minified) shouldBe true
      }

      "take a source-mapped file for generated code, however it is wrapped" in {
          val wrapped = (0 until 200).map(i => s"export function f$i(a) {\n  return a + $i;\n}")
              .mkString("\n") + "\n//# sourceMappingURL=app.js.map\n"
          JsGeneratedFiles.looksGenerated(wrapped) shouldBe true
          JsGeneratedFiles.looksGenerated(
            wrapped.replace("sourceMappingURL", "sourceName")
          ) shouldBe
              false
      }

      "skip nothing unless switched on" in {
          JsGeneratedFiles.enabled shouldBe false
          val cpg = fixture()
          io.appthreat.x2cpg.passes.taggers.js.JsContext(
            cpg,
            io.appthreat.x2cpg.passes.taggers.js.JsModules(cpg),
            io.appthreat.x2cpg.passes.taggers.js.JsTagger(
              new overflowdb.BatchedUpdate.DiffGraphBuilder
            )
          ).generatedFiles shouldBe empty
      }
  }

  // ---------------------------------------------------------------------------------------------
  // Scaling
  // ---------------------------------------------------------------------------------------------

  private val Ratio = 2.2

  private def runCounted(files: Seq[(String, String)]): Map[String, Long] =
    val cpg = files.tail.foldLeft(code(files.head._1, files.head._2))((c, f) =>
        c.moreCode(f._1, f._2)
    )
    JsStats.reset()
    new JsFrameworkRecognizersPass(cpg).createAndApply()
    Seq(
      "build.calls",
      "lookup.calls",
      "visit.callersOf",
      "compute.callersOf",
      "compute.predicateFunction",
      "lookup.methodsInFile",
      "lookup.typeDecls",
      "visit.instanceReads"
    ).map(k => k -> JsStats.get(k)).toMap

  /** One minified bundle: `n` functions all named `e` (each holding a parameter in a closure, so
    * the bridges ask who calls it), `n` calls of them by member, and `n` guard-shaped calls of
    * names nothing resolves. Everything is in one file.
    */
  private def bundle(n: Int): Map[String, Long] =
    val body = (0 until n).map { i =>
        s"o.e=function e(t){return function(){return t}};var v$i=o.e(window.q($i));if(!o.k(v$i))o.q(v$i);"
    }.mkString("var s=location.hash;var o={};\n", "\n", "")
    runCounted(Seq(body -> "dist/chunk.js"))

  /** `n` modules, each with a class keeping a source in a field that an instance of it is read
    * through, and a function whose closure captures its parameter.
    */
  private def modules(n: Int): Map[String, Long] =
      runCounted((0 until n).map { i =>
          s"""
        |class C$i { ngOnInit() { this.f$i = location.hash; } }
        |export function use$i(p) { const g = () => document.write(p); return g; }
        |export function make$i() { const c = new C$i(); return c.f$i; }
        |""".stripMargin -> s"src/m$i.ts"
      })

  private lazy val smallBundle  = bundle(8)
  private lazy val largeBundle  = bundle(16)
  private lazy val smallModules = modules(8)
  private lazy val largeModules = modules(16)

  "The taggers' lookups" should {

      "build each index once per run, whatever the size of the project" in {
          smallBundle("build.calls") shouldBe 1L
          largeBundle("build.calls") shouldBe 1L
          largeModules("build.calls") shouldBe 1L
      }

      "ask the call index, not the graph, for the callers of a function" in {
          smallBundle("visit.callersOf") should be > 0L
          largeBundle("visit.callersOf").toDouble should be <=
              smallBundle("visit.callersOf") * Ratio
      }

      "answer the callers of a function once for the whole run, not once per round" in {
          // the bridges ask again in every fixpoint round and every pipeline round
          smallBundle("compute.callersOf") shouldBe 8L
          largeBundle("compute.callersOf") shouldBe 16L
      }

      "resolve a guard's callee once per calling file and name" in {
          // `o.k(...)` and `o.q(...)`: two names in one file, however many calls
          smallBundle("compute.predicateFunction") should be > 0L
          // through the (file, name) index, not a scan of the files' methods
          smallBundle("lookup.methodsInFile") should be > 0L
          largeBundle("compute.predicateFunction") shouldBe smallBundle("compute.predicateFunction")
      }

      "visit only the field accesses that name the member, when finding reads off an instance" in {
          smallModules("visit.instanceReads") should be > 0L
          // the class of each write is found through the type-declaration index
          smallModules("lookup.typeDecls") should be > 0L
          largeModules("visit.instanceReads").toDouble should be <=
              smallModules("visit.instanceReads") * Ratio
      }
  }
end JsIndexesTest
