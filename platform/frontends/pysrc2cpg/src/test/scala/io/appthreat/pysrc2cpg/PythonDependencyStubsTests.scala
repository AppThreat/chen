package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.queryengine.{EngineConfig, EngineContext}
import io.appthreat.dataflowengineoss.queryengine.summaries.{FlowSummaryTags, MethodFlowSummary}
import io.appthreat.x2cpg.PythonDepsMode
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*

/** `python-deps=stubs|summaries`: dependency distributions enter the graph as external signatures
  * only, in both re-export spellings, and nothing else about the graph changes. Every "must exist"
  * assertion is paired with the near-miss: the stub that must stay external, the unimported
  * distribution that must not be ingested, the alias that must not be created twice.
  */
class PythonDependencyStubsTests extends PySrc2CpgFixture(withOssDataflow = true):

  /** A miniature "flask" distribution: a class re-exported from `__init__.py`, a function
    * re-exported from a sibling module, and an unimported distribution ("boto3") that must never be
    * ingested.
    */
  private def writeFakeVenv(dir: java.io.File): Unit =
    val sp = dir.toPath.resolve(".venv/lib/python3.14/site-packages")
    Files.createDirectories(sp.resolve("flask"))
    Files.write(
      sp.resolve("flask/__init__.py"),
      """from .app import Flask
        |from .templating import render_template_string
        |from .helpers import passthrough, sanitize, decorate
        |from .globals import request, DEFAULT_NAME
        |""".stripMargin.getBytes
    )
    Files.write(
      sp.resolve("flask/app.py"),
      """class Flask:
        |    def __init__(self, import_name):
        |        self.import_name = import_name
        |
        |    def route(self, rule, **options):
        |        def decorator(f):
        |            f.rule = rule
        |            return f
        |        return decorator
        |""".stripMargin.getBytes
    )
    Files.write(
      sp.resolve("flask/templating.py"),
      """def render_template_string(source, **context):
        |    return source
        |""".stripMargin.getBytes
    )
    // The pair the summary machinery exists for: two library functions with the same
    // signature, one of which carries its argument to its result and one of which does not.
    // Nothing but the library's own body distinguishes them.
    Files.write(
      sp.resolve("flask/helpers.py"),
      """def passthrough(body):
        |    return body
        |
        |def sanitize(body):
        |    return "safe"
        |
        |def decorate(rule):
        |    def wrapper(f):
        |        f.rule = rule
        |        return f
        |    return wrapper
        |""".stripMargin.getBytes
    )
    // Module-level *values* re-exported from `__init__.py`. Flask's `request`, `session` and
    // `g`, requests' `codes`, django's `settings` all have this shape, and user code imports
    // them far more often than it imports the classes behind them.
    Files.write(
      sp.resolve("flask/globals.py"),
      """from .app import Flask
        |
        |request = Flask("proxy")
        |DEFAULT_NAME: str = "flask"
        |""".stripMargin.getBytes
    )
    // An imported-free distribution: guards the "ingest only what is imported" rule.
    Files.createDirectories(sp.resolve("boto3"))
    Files.write(
      sp.resolve("boto3/__init__.py"),
      """def client(name):
        |    return name
        |""".stripMargin.getBytes
    )
  end writeFakeVenv

  private val userApp =
      """
        |from flask import Flask, render_template_string, passthrough
        |
        |app = Flask(__name__)
        |
        |def index(user_input):
        |    return render_template_string(passthrough(user_input))
        |""".stripMargin

  private val stubsCpg = code(userApp, "app.py")
      .withPythonDeps(PythonDepsMode.Stubs)
      .withProjectSetup(writeFakeVenv)

  "python-deps=none (default)" should:

    "keep the graph free of dependency nodes" in:
      val cpg = code(userApp, "app.py").withProjectSetup(writeFakeVenv)
      cpg.typeDecl.fullNameExact("flask.app.Flask").l shouldBe empty
      cpg.method.filenameExact("flask/app.py").l shouldBe empty
      cpg.typeDecl.fullName(".*boto3.*").l shouldBe empty

  "python-deps=stubs" should:

    "create external signature stubs for imported distributions" in:
      val route = stubsCpg.method.fullNameExact("flask.app.Flask.route").head
      route.isExternal shouldBe true
      // Signature survives: the parameter names and positions are intact
      // (`**options` is the variadic keyword parameter).
      (route.parameter.name.l should contain).theSameElementsInOrderAs(List(
        "self",
        "rule",
        "options"
      ))
      // No body, no CFG: the block is empty and no call survives inside the stub.
      route.block.astChildren.l shouldBe empty
      route.ast.isCall.l shouldBe empty

    "keep the project's own code internal" in:
      val index = stubsCpg.method.nameExact("index").head
      index.isExternal shouldBe false
      index.filename shouldBe "app.py"

    "not ingest distributions the project does not import" in:
      stubsCpg.method.fullNameExact("boto3.client").l shouldBe empty
      stubsCpg.typeDecl.fullName(".*boto3.*").l shouldBe empty

    "create both re-export spellings exactly once" in:
      // `from flask import Flask` joins `flask.Flask` (the real
      // `__init__.py` re-export) and `flask.Flask` (the alias spelling the
      // import resolver generates). A method alias is a METHOD plus its TYPE_DECL twin
      // (the python visitor's convention); each kind must exist exactly once - the
      // near-miss guard against creating a stub twice.
      val classAliases =
          List("flask.Flask", "flask.Flask")
      classAliases.foreach { fullName =>
          withClue(s"$fullName: ") {
              stubsCpg.typeDecl.fullNameExact(fullName).size shouldBe 1
          }
      }
      val methodAliases = List(
        "flask.render_template_string",
        "flask.render_template_string",
        "flask.passthrough",
        "flask.passthrough",
        "flask.Flask.__init__",
        "flask.Flask.__init__"
      )
      methodAliases.foreach { fullName =>
        withClue(s"$fullName (method): ") {
            stubsCpg.method.fullNameExact(fullName).size shouldBe 1
        }
        withClue(s"$fullName (type decl twin): ") {
            stubsCpg.typeDecl.fullNameExact(fullName).size shouldBe 1
        }
      }

    "keep dependency signatures but no dependency bodies" in:
      // Function bodies were truncated at the parser-AST level: the `__init__` stub has
      // its parameters and an empty block, and nothing else - no LOCALs, no IDENTIFIERs,
      // no CFG beyond the (empty) block.
      val init = stubsCpg.method.fullNameExact("flask.app.Flask.__init__").head
      init.block.astChildren.l shouldBe empty
      init.ast.isCall.l shouldBe empty
      init.ast.isLocal.l shouldBe empty
      init.ast.isIdentifier.l shouldBe empty

    "resolve user calls into the dependency" in:
      // `render_template_string` and `passthrough` resolve through the re-export aliases.
      val renderCall = stubsCpg.call.nameExact("render_template_string").head
      renderCall.methodFullName should (
        startWith("flask.").or(
          startWith("flask.templating.")
        )
      )
      renderCall.callee(using NoResolve).l should not be empty

      val passthroughCall = stubsCpg.call.nameExact("passthrough").head
      passthroughCall.methodFullName should (
        startWith("flask.").or(
          startWith("flask.helpers.")
        )
      )

      // The Flask constructor call resolves to a real `__init__` stub, not `<unknown>`.
      val flaskCtor = stubsCpg.call.nameExact("Flask").head
      flaskCtor.methodFullName should endWith(".Flask.__init__")
      (flaskCtor.methodFullName should not).include("<unknown")

    "keep module-level values a package re-exports" in:
      // `from flask import request` is the single most common shape in real Flask code, and
      // the same shape carries requests' `codes` and django's `settings`. Truncating the
      // module level down to imports/defs/classes drops the assignment that defines the
      // value, so the symbol vanishes: the alias planner finds no target, the user's
      // `request` resolves to nothing, and the identifier that WOULD have been typed by
      // recovery is now backed by a package the graph knows to have no such member.
      val moduleLocals =
          stubsCpg.method.fullNameExact("flask.globals").local.name.l
      withClue(
        s"locals of the ingested flask/globals.py module: [${moduleLocals.mkString(", ")}]"
      ) {
          moduleLocals should contain("request")
          moduleLocals should contain("DEFAULT_NAME")
      }

  "python-deps=summaries" should:

    "persist flow summaries computed from the dependency bodies" in:
      val cpg = code(userApp, "app.py")
          .withPythonDeps(PythonDepsMode.Summaries)
          .withProjectSetup(writeFakeVenv)
      val summaries = FlowSummaryTags.fromCpg(cpg)
      summaries.keySet should contain("flask.helpers.passthrough")

      // `passthrough(body): return body` - parameter 1 reaches the return.
      val summary: MethodFlowSummary = summaries("flask.helpers.passthrough")
      summary.reachesReturn(1) shouldBe true

      // The alias carries the same facts so callers through either spelling are covered.
      summaries.get("flask.passthrough").foreach { aliasSummary =>
          aliasSummary.reachesReturn(1) shouldBe true
      }

    "keep the dependency methods bodyless and external" in:
      val cpg = code(userApp, "app.py")
          .withPythonDeps(PythonDepsMode.Summaries)
          .withProjectSetup(writeFakeVenv)
      val passthrough: Method =
          cpg.method.fullNameExact("flask.helpers.passthrough").head
      passthrough.isExternal shouldBe true
      passthrough.block.astChildren.l shouldBe empty

  "python-deps=full" should:

    "ingest the whole venv as external code with bodies" in:
      val cpg = code(userApp, "app.py")
          .withPythonDeps(PythonDepsMode.Full)
          .withProjectSetup(writeFakeVenv)
      // Full mode ingests through the dependency origins: file names are site-packages
      // relative, every node is external (attribution), and bodies are intact (explorable).
      val route: Method = cpg.method.fullNameExact("flask.app.Flask.route").head
      route.isExternal shouldBe true
      // Bodies intact: the decorator's inner structure is present.
      route.ast.isCall.nameNot("<operator>").l should not be empty
      route.ast.isReturn.l should not be empty
end PythonDependencyStubsTests

/** Task 7.1: what `summaries` mode is actually worth.
  *
  * The engine's default for a callee it cannot look inside is permissive - every argument taints
  * the call's result. So `python-deps=stubs` on its own barely moves flows: taint already crossed
  * the library boundary, it just crossed it for every library function alike, `sanitize` and
  * `passthrough` treated identically. The summaries computed from the dependency's real source
  * become declared flow semantics, and a declared semantic is authoritative - which is what finally
  * lets the two be told apart.
  *
  * The suite is written as a matched triple against the SAME library and the SAME user code, so
  * every assertion is paired with its near-miss:
  *   - `passthrough` really does carry its argument out: the flow must survive, or the mode is
  *     simply deleting results.
  *   - `sanitize` provably does not: the flow must disappear, or the mode buys nothing.
  *   - `decorate` captures its argument in a closure, where an intra-procedural summary cannot see
  *     it: the flow must survive, because summarising it as inert would cut every flow through a
  *     decorator factory - and that is how much of the Python web ecosystem is written.
  */
class PythonDependencySummarySemanticsTests extends PySrc2CpgFixture(withOssDataflow = true):

  private def writeFakeVenv(dir: java.io.File): Unit =
    val sp = dir.toPath.resolve(".venv/lib/python3.14/site-packages")
    Files.createDirectories(sp.resolve("flask"))
    Files.write(
      sp.resolve("flask/__init__.py"),
      """from .helpers import passthrough, sanitize, decorate
        |from .templating import render_template_string
        |""".stripMargin.getBytes
    )
    Files.write(
      sp.resolve("flask/helpers.py"),
      """def passthrough(body):
        |    return body
        |
        |def sanitize(body):
        |    return "safe"
        |
        |def decorate(rule):
        |    def wrapper(f):
        |        f.rule = rule
        |        return f
        |    return wrapper
        |""".stripMargin.getBytes
    )
    Files.write(
      sp.resolve("flask/templating.py"),
      """def render_template_string(source, **context):
        |    return source
        |""".stripMargin.getBytes
    )
  end writeFakeVenv

  private val userApp =
      """
        |from flask import render_template_string, passthrough, sanitize, decorate
        |
        |def carried(user_input):
        |    return render_template_string(passthrough(user_input))
        |
        |def blocked(user_input):
        |    return render_template_string(sanitize(user_input))
        |
        |def captured(user_input):
        |    return render_template_string(decorate(user_input))
        |""".stripMargin

  private def flowCount(cpg: Cpg, methodName: String): Int =
    val source = cpg.method.nameExact(methodName).parameter.nameExact("user_input")
    val sink   = cpg.call.nameExact("render_template_string").argument
    sink.reachableByFlows(source).size

  private lazy val stubsCpg = code(userApp, "app.py")
      .withPythonDeps(PythonDepsMode.Stubs)
      .withProjectSetup(writeFakeVenv)

  private lazy val summariesCpg = code(userApp, "app.py")
      .withPythonDeps(PythonDepsMode.Summaries)
      .withProjectSetup(writeFakeVenv)

  "python-deps=stubs (no summaries)" should:

    "treat every library call alike, because an unknown callee is permissive" in:
      // This is the baseline the mode has to beat: `sanitize` manufactures a flow it has no
      // business manufacturing, and nothing in the graph can tell it apart from `passthrough`.
      withClue("carried: ")(flowCount(stubsCpg, "carried") should be > 0)
      withClue("blocked (the false positive summaries must remove): ")(
        flowCount(stubsCpg, "blocked") should be > 0
      )

  "python-deps=summaries" should:

    "keep the flow through a library function that really carries its argument" in:
      withClue("passthrough returns its parameter; the flow must survive: ")(
        flowCount(summariesCpg, "carried") should be > 0
      )

    "drop the flow through a library function that provably does not" in:
      // `sanitize` discards `body` and returns a literal. The summary says so, the summary
      // becomes a semantic, and the semantic stops the call result carrying taint.
      withClue("sanitize discards its parameter; the flow must be gone: ")(
        flowCount(summariesCpg, "blocked") shouldBe 0
      )

    "keep the flow where the summary cannot see the truth" in:
      // `decorate` captures `rule` inside a nested function, which is a separate METHOD: no
      // intra-procedural REACHING_DEF path connects parameter to return. Summarising it would
      // be an under-report, so it is left unsummarised and stays permissive.
      withClue("decorate captures its parameter in a closure; the flow must survive: ")(
        flowCount(summariesCpg, "captured") should be > 0
      )

    "leave the project's own methods without derived semantics" in:
      // Only external methods qualify: an internal method is explored by the engine itself,
      // and a semantic would replace that exploration with an approximation of it.
      val derived = FlowSummaryTags.externalSemantics(summariesCpg).map(_.methodFullName).toSet
      withClue(s"derived semantics: [${derived.toSeq.sorted.mkString(", ")}]") {
          derived.foreach(_ should not startWith "app.py")
          derived should contain("flask.helpers.sanitize")
          derived should not contain "flask.helpers.decorate"
      }
end PythonDependencySummarySemanticsTests
