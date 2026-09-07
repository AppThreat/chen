package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.language.*
import io.appthreat.dataflowengineoss.queryengine.summaries.FlowSummaryTags
import io.appthreat.pysrc2cpg.PythonDependencyStubs.ModuleScope
import io.appthreat.x2cpg.PythonDepsMode
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*

import java.nio.file.{Files, Path, Paths}
import scala.jdk.CollectionConverters.*

/** `python-deps=full`: the whole dependency tree in the graph, connected. Everything the thin modes
  * do deliberately NOT do is asserted here, each against its near-miss: the whole tree and not the
  * import closure, bodies intact and not truncated, external for attribution while the engine still
  * descends into the real statements, package identity on every node it covers, and no flow-summary
  * approximation layered on top of bodies the engine can explore.
  */
class PythonDependencyFullTests extends PySrc2CpgFixture(withOssDataflow = true):

  private val spSubdir = ".venv/lib/python3.14/site-packages"

  /** A miniature installed world: an imported package with re-exports and real bodies, an
    * UNIMPORTED package (the import closure would miss it), a namespace package without
    * `__init__.py`, a `.dist-info` for identity, a `.py`/`.pyi` pair, and a PDM layout.
    */
  private def writeFullVenv(dir: java.io.File): Unit =
    val sp = dir.toPath.resolve(spSubdir)
    Files.createDirectories(sp.resolve("flask"))
    Files.write(
      sp.resolve("flask/__init__.py"),
      """from .helpers import passthrough, sanitize, decorate
        |from .app import Flask
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
    // Distribution identity for `flask` with an import name that differs from nothing - the
    // simple case; top_level.txt handling is exercised by `otherpkg` below.
    Files.createDirectories(sp.resolve("flask-3.0.3.dist-info"))
    Files.write(sp.resolve("flask-3.0.3.dist-info/METADATA"), "Metadata-Version: 2.1\n".getBytes)
    // An unimported distribution: full mode ingests it, stubs must not.
    Files.createDirectories(sp.resolve("boto3"))
    Files.write(
      sp.resolve("boto3/__init__.py"),
      """def client(name):
        |    return name
        |""".stripMargin.getBytes
    )
    // A wheel-name-vs-import-name mismatch only top_level.txt resolves.
    Files.createDirectories(sp.resolve("other_lib-2.1.0.dist-info"))
    Files.write(sp.resolve("other_lib-2.1.0.dist-info/top_level.txt"), "otherpkg\n".getBytes)
    Files.createDirectories(sp.resolve("otherpkg"))
    Files.write(
      sp.resolve("otherpkg/__init__.py"),
      """def hidden(x):
        |    return x
        |""".stripMargin.getBytes
    )
    // A namespace package: no __init__.py, no .dist-info - must not silently drop out.
    Files.createDirectories(sp.resolve("nspkg/sub"))
    Files.write(
      sp.resolve("nspkg/sub/mod.py"),
      """def nspkg_fn(x):
        |    return x
        |""".stripMargin.getBytes
    )
    // A .py/.pyi pair: the stub wins as the API contract.
    Files.write(
      sp.resolve("dual.py"),
      """def f(x):
        |    return x + 1
        |""".stripMargin.getBytes
    )
    Files.write(
      sp.resolve("dual.pyi"),
      """def f(x: int) -> int: ...
        |""".stripMargin.getBytes
    )
  end writeFullVenv

  private val userApp =
      """
        |from flask import Flask, passthrough, sanitize, decorate
        |
        |app = Flask(__name__)
        |
        |def carried(user_input):
        |    out = passthrough(user_input)
        |    render(out)
        |
        |def blocked(user_input):
        |    out = sanitize(user_input)
        |    render(out)
        |
        |def captured(user_input):
        |    out = decorate(user_input)
        |    render(out)
        |""".stripMargin

  private lazy val fullCpg = code(userApp, "app.py")
      .withPythonDeps(PythonDepsMode.Full)
      .withProjectSetup(writeFullVenv)

  /** The oracle: does the parameter reach the ARGUMENT of the downstream `render` call - i.e. does
    * the library function's RESULT carry the taint. (Not `methodReturn.reachableByFlows(param)`:
    * that answers "is the parameter live at exit", which the method-exit approximation satisfies
    * for any used parameter, library or no library.)
    */
  private def flowCount(cpg: io.shiftleft.codepropertygraph.Cpg, methodName: String): Int =
    val source = cpg.method.nameExact(methodName).parameter.nameExact("user_input")
    cpg.call.nameExact("render").argument.reachableByFlows(source).size

  "python-deps=full ingestion" should:

    "ingest every file under the origin, not the import closure" in:
      // boto3 is never imported; full mode ingests it anyway - a module imported only
      // dynamically is precisely what the thin modes miss.
      fullCpg.method.fullNameExact("boto3.client").l should not be empty
      fullCpg.method.fullNameExact("nspkg.sub.mod.nspkg_fn").l should not be empty

    "keep dependency bodies intact" in:
      // truncateForSignatures must not run: the decorator's nested structure is real
      // statements, and `passthrough`'s return carries its parameter.
      val decorator = fullCpg.method.fullNameExact("flask.app.Flask.route").head
      decorator.ast.isCall.nameNot("<operator>").l should not be empty
      val passthrough = fullCpg.method.fullNameExact("flask.helpers.passthrough").head
      passthrough.ast.isReturn.l should not be empty

    "mark dependency methods external for attribution" in:
      fullCpg.method.fullNameExact("flask.helpers.passthrough").head.isExternal shouldBe true
      fullCpg.typeDecl.fullNameExact("flask.app.Flask").head.isExternal shouldBe true
      // ...while the project's own code stays internal.
      fullCpg.method.nameExact("carried").head.isExternal shouldBe false

    "let the engine descend into the real library bodies" in:
      // Explorability is its own notion now: `passthrough` really returns its parameter so the
      // flow survives the descent, and `sanitize` really discards it so the manufactured
      // permissive flow is refuted by the real body - without needing `summaries` to say so.
      // `decorate` captures its parameter in a nested METHOD the intra-procedural descent
      // cannot see - it stays permissive.
      withClue("carried (passthrough returns its parameter): ")(
        flowCount(fullCpg, "carried") should be > 0
      )
      withClue("blocked (sanitize discards it - the real body refutes the flow): ")(
        flowCount(fullCpg, "blocked") shouldBe 0
      )
      withClue("captured (decorate hides it in a closure): ")(
        flowCount(fullCpg, "captured") should be > 0
      )

    "refute no less than summaries mode does, without needing summaries" in:
      // The Task 7.1 win, achieved by exploration instead of declaration: the same matched
      // triple on a `summaries` build of the SAME venv agrees on every case.
      val summariesCpg = code(userApp, "app.py")
          .withPythonDeps(PythonDepsMode.Summaries)
          .withProjectSetup(writeFullVenv)
      withClue("carried: ")(flowCount(summariesCpg, "carried") shouldBe flowCount(
        fullCpg,
        "carried"
      ))
      withClue("blocked: ")(flowCount(summariesCpg, "blocked") shouldBe flowCount(
        fullCpg,
        "blocked"
      ))
      withClue("captured: ")(flowCount(summariesCpg, "captured") shouldBe flowCount(
        fullCpg,
        "captured"
      ))

    "attach package identity from .dist-info, honouring top_level.txt" in:
      val flaskPurl   = "pkg:pypi/flask@3.0.3"
      val otherPurl   = "pkg:pypi/other_lib@2.1.0"
      val passthrough = fullCpg.method.fullNameExact("flask.helpers.passthrough").head
      passthrough.tag.name.l should contain(flaskPurl)
      // The wheel name is `other_lib` but the import name is `otherpkg`: only top_level.txt
      // maps it, and the mapping is what reachables attribution keys on.
      val hidden = fullCpg.method.fullNameExact("otherpkg.hidden").head
      hidden.tag.name.l should contain(otherPurl)
      // Files without any .dist-info (vendored code) are ingested without identity, not dropped.
      val nspkgFn = fullCpg.method.fullNameExact("nspkg.sub.mod.nspkg_fn").head
      nspkgFn.tag.name.l.filter(_.startsWith("pkg:")) shouldBe empty

    "prefer a .pyi over a .py for the same module" in:
      // `dual.py` and `dual.pyi` both exist: one module, the stub's signature shape.
      val fromPyi = fullCpg.method.filenameExact("dual.pyi")
      fromPyi.nameExact(ModuleScope).l should not be empty
      fullCpg.method.filenameExact("dual.py").l shouldBe empty

    "not combine with summaries" in:
      // Bodies are explorable, so a declared semantic would REPLACE exploration with an
      // approximation of it - the worst of both bets. Full never writes flow-summary tags,
      // and externalSemantics derives nothing from a full-mode graph.
      FlowSummaryTags.fromCpg(fullCpg) shouldBe empty
      FlowSummaryTags.externalSemantics(fullCpg) shouldBe empty

    "resolve user calls into the real dependency code" in:
      // No synthetic aliases exist in full mode: `from flask import passthrough` must join the
      // real `__init__.py` re-export chain natively.
      val call = fullCpg.call.nameExact("passthrough").head
      call.callee(using NoResolve).fullName.l should contain("flask.helpers.passthrough")

    "ingest an out-of-tree venv given an absolute venv-dir" in:
      // The common real-world layout the legacy walk could not see: the venv lives outside
      // the project directory.
      val outside = Files.createTempDirectory("task085-oov-venv")
      try
        val sp = outside.resolve("lib/python3.14/site-packages/flask")
        Files.createDirectories(sp)
        Files.write(
          sp.resolve("__init__.py"),
          """from .helpers import passthrough
              |""".stripMargin.getBytes
        )
        Files.write(
          sp.resolve("helpers.py"),
          """def passthrough(body):
              |    return body
              |""".stripMargin.getBytes
        )
        val cpg = code("from flask import passthrough\n", "app.py")
            .withPythonDeps(PythonDepsMode.Full)
            .withVenvDir(outside)
        cpg.method.fullNameExact("flask.helpers.passthrough").l should not be empty
        cpg.method.fullNameExact("flask.helpers.passthrough").head.isExternal shouldBe
            true
      finally
        Files.walk(outside).sorted(java.util.Comparator.reverseOrder()).forEach(_.toFile.delete)
      end try

    "resolve a PDM __pypackages__ layout" in:
      val cpg = code("import pdmpkg\n", "app.py")
          .withPythonDeps(PythonDepsMode.Full)
          .withProjectSetup { dir =>
            // The real PEP 582 spelling has trailing underscores. It is also a name on the
            // ingestion ignore list, so this asserts that the ignore list is applied to the
            // path BELOW the origin - judging the absolute path would discard every file the
            // origin exists to contribute.
            val lib = dir.toPath.resolve("__pypackages__/3.14/lib/pdmpkg")
            Files.createDirectories(lib)
            Files.write(
              lib.resolve("__init__.py"),
              """def value():
                  |    return 1
                  |""".stripMargin.getBytes
            )
          }
      cpg.method.fullNameExact("pdmpkg.value").l should not be empty

    "ingest typeshed stdlib signatures when configured" in:
      val typeshed = Files.createTempDirectory("task085-typeshed")
      try
        Files.createDirectories(typeshed.resolve("stdlib/versions/3.14"))
        Files.createDirectories(typeshed.resolve("stdlib/os"))
        Files.write(
          typeshed.resolve("stdlib/posixpath.pyi"),
          """def join(a: str, *p: str) -> str: ...
              |""".stripMargin.getBytes
        )
        Files.write(
          typeshed.resolve("stdlib/versions/3.14/dummy.pyi"),
          """def only_new(x: int) -> int: ...
              |""".stripMargin.getBytes
        )
        val cpg = code("import posixpath\n", "app.py")
            .withPythonDeps(PythonDepsMode.Full)
            .withTypeshedDir(typeshed)
        val join = cpg.method.fullNameExact("posixpath.join").head
        join.isExternal shouldBe true
        // A .pyi body is `...`: no RETURN statement, so the method is NOT explorable and a
        // call to it keeps the engine's permissive default instead of dying at an empty
        // descent - the stdlib-recall guarantee.
        io.shiftleft.semanticcpg.language.MethodExplorability.isExplorable(join) shouldBe false
      finally
        Files.walk(typeshed).sorted(java.util.Comparator.reverseOrder()).forEach(_.toFile.delete)
      end try

    "keep a project module that collides with a dependency module name" in:
      // The project's own `helpers.py` and site-packages' `flask/helpers.py` never collide,
      // but a top-level dependency module named like a project file would: the project wins
      // and stays internal.
      val cpg = code("def x(): return 1\n", "dual.py")
          .withPythonDeps(PythonDepsMode.Full)
          .withProjectSetup(writeFullVenv)
      val projectModule = cpg.method.filenameExact("dual.py").nameExact(ModuleScope).head
      projectModule.isExternal shouldBe false

  "externality by path (regardless of mode)" should:

    "mark walked venv files external under ignore-venv-dir=false" in:
      val cpg = code(userApp, "app.py")
          .withIgnoreVenvDir(false)
          .withProjectSetup(writeFullVenv)
      // The legacy walk parses `.venv/...`-prefixed files; the path-based marker must
      // attribute them as dependency code even in `none` mode.
      val route = cpg.method.nameExact("route")
          .find(_.filename.contains("flask/app.py")).head
      route.isExternal shouldBe true
      cpg.method.nameExact("carried").head.isExternal shouldBe false

    "keep a project file named like a venv marker internal" in:
      // Near-miss both ways: `venv_utils.py` is a FILE named like a marker - only directory
      // segments count - and it stays internal in every mode.
      val cpg = code("def util(): return 1\n", "venv_utils.py")
          .withIgnoreVenvDir(false)
          .withProjectSetup(writeFullVenv)
      cpg.method.filenameExact("venv_utils.py").nameExact("util").head.isExternal shouldBe false
end PythonDependencyFullTests
