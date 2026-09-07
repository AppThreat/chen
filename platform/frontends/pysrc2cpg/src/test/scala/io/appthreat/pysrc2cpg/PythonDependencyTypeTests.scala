package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.PythonDepsMode
import io.shiftleft.semanticcpg.language.*

import java.nio.file.Files

/** Task 8: the ingested signatures must pay off for TYPES. Every mechanism is asserted together
  * with its near-miss: the type that must NOT be invented (a bare name the graph cannot back stays
  * bare), and the `python-deps=none` graph where none of this may appear.
  *
  * The fake distribution is shaped so each failure mode of the pre-task graph has one test:
  *   - `url_for` names BOTH a module-level function (re-exported from `__init__.py`) and a method
  *     of the ingested `Flask` class - the class member must not shadow the module function.
  *   - `request` is a module-level annotated binding (`request: Flask = ...`) - the member's bare
  *     annotation name must become a TYPE_DECL-backed full name.
  *   - `redirect` returns a class imported in its OWN module - the re-export alias must carry the
  *     canonical return, though the alias's synthetic file imports nothing.
  *   - `Flask` inherits `config` from `Base` - a member load through the dependency hierarchy must
  *     resolve to the base's declared member type.
  */
class PythonDependencyTypeTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def writeFakeVenv(dir: java.io.File): Unit =
    val sp = dir.toPath.resolve(".venv/lib/python3.14/site-packages")
    Files.createDirectories(sp.resolve("flask"))
    Files.write(
      sp.resolve("flask/__init__.py"),
      """from .app import Flask
        |from .globals import request
        |from .helpers import redirect, url_for, wobble
        |""".stripMargin.getBytes
    )
    Files.write(
      sp.resolve("flask/app.py"),
      """class Config:
        |    DEBUG: bool = True
        |
        |class MultiDict:
        |    def get(self, name, default=None) -> str:
        |        return name
        |
        |class Base:
        |    config: Config
        |
        |class Request(Base):
        |    @property
        |    def args(self) -> MultiDict:
        |        return MultiDict()
        |
        |class Flask(Request):
        |    def __init__(self, import_name):
        |        self.import_name = import_name
        |
        |    def url_for(self, endpoint) -> str:
        |        return endpoint
        |""".stripMargin.getBytes
    )
    Files.write(
      sp.resolve("flask/globals.py"),
      """import typing as t
        |
        |if t.TYPE_CHECKING:
        |    from .app import Flask, Request
        |
        |request: Request = None
        |current_app: Flask = None
        |site: NotImported = "nowhere"
        |
        |if t.TYPE_CHECKING:
        |    import os
        |    os_sep = os.sep
        |""".stripMargin.getBytes
    )
    Files.write(
      sp.resolve("flask/helpers.py"),
      """from .app import Flask
        |
        |class Response:
        |    status = "200"
        |
        |def redirect(location) -> Response:
        |    return Response(location)
        |
        |def url_for(endpoint):
        |    return endpoint
        |
        |def wobble() -> Widget:
        |    return None
        |""".stripMargin.getBytes
    )
  end writeFakeVenv

  private val userApp =
      """
      |from flask import Flask, request, redirect, url_for, wobble, current_app
      |
      |app = Flask("micro")
      |cfg = app.config
      |loc = url_for("index")
      |r = redirect("/x")
      |w = wobble()
      |nm = request.import_name
      |ghost = app.banana
      |qs = request.args
      |pg = qs.get("page")
      |nf = request.url_for
      |ca = current_app
      |""".stripMargin

  private lazy val stubsCpg = code(userApp, "app.py")
      .withPythonDeps(PythonDepsMode.Stubs)
      .withProjectSetup(writeFakeVenv)

  private def urlForCall = stubsCpg.call.nameExact("url_for").head

  "python-deps=stubs - ingested signatures pay off for types" should:

    "resolve a module function whose name a class member shares" in:
      // `Flask.url_for` is a method member of an ingested class; `url_for` is ALSO a
      // module-level function re-exported by the package. The import must resolve to the
      // module function (a real METHOD in the graph), never to the class member.
      val call = urlForCall
      call.methodFullName should startWith("flask")
      (call.methodFullName should not).endWith("Flask.url_for")
      call.callee(using NoResolve).l should not be empty

    "type a re-exported module binding with its declared class" in:
      // `request: Request` and `current_app: Flask` in flask/globals.py - both bound under a
      // `TYPE_CHECKING` guard. The members' annotations are canonicalized against the file's
      // own bindings, so the user's identifiers carry TYPE_DECL-backed full names instead of
      // the bare annotation names. (The import may also carry the module-object path as a
      // secondary candidate - that is the pre-existing re-export spelling, not the annotation.)
      val requestIds = stubsCpg.identifier.nameExact("request").typeFullName.l.distinct
      requestIds should contain("flask.app.Request")
      requestIds should not contain "Request"
      val currentAppIds = stubsCpg.identifier.nameExact("current_app").typeFullName.l.distinct
      currentAppIds should contain("flask.app.Flask")
      currentAppIds should not contain "Flask"

    "carry the target's canonical return type through a re-export alias" in:
      // `redirect` returns `Response`, imported in flask/helpers.py but NOT in
      // flask/__init__.py. The alias's synthetic file imports nothing, so the
      // canonicalization must happen against the TARGET's bindings when the alias is
      // created - the later type-hint pass cannot rescue it: it only knows the imports
      // of the file the alias lives in.
      val redirectTypes = stubsCpg.call.nameExact("redirect").typeFullName.l.distinct
      redirectTypes shouldBe List("flask.helpers.Response")
      stubsCpg.identifier.nameExact("r").typeFullName.l.distinct shouldBe List(
        "flask.helpers.Response"
      )

    "type a member inherited from an ingested base class" in:
      // `config` is declared on `Base`; `app` is a `Flask`. The field load must walk the
      // dependency's class hierarchy to the declaring base.
      stubsCpg.identifier.nameExact("cfg").typeFullName.l.distinct shouldBe List(
        "flask.app.Config"
      )

    "read a dependency property's declared return at a field load" in:
      // `args` is a @property of the ingested Request class: `request.args` is a computed
      // value, and its type is the getter's declared return - through which `.get` then
      // resolves and returns its own declared type.
      stubsCpg.identifier.nameExact("qs").typeFullName.l.distinct should contain(
        "flask.app.MultiDict"
      )
      stubsCpg.identifier.nameExact("pg").typeFullName.l.distinct.map(_.takeWhile(_ != '.')) should
          contain("__builtin")

    "not read an ordinary method's return at a field load" in:
      // `url_for` is a plain method: `request.url_for` is a bound method, not the method's
      // return value, so the property mechanism must not fire for it.
      val nfTypes = stubsCpg.identifier.nameExact("nf").typeFullName.l.distinct
      nfTypes should not contain "__builtin.str"
      nfTypes should not contain "str"

    "not invent a type for a member no class declares" in:
      // The hierarchy walk is not a license to make types up: `banana` is declared nowhere,
      // so `ghost` may carry at most a placeholder - never a type a TYPE_DECL backs.
      val ghostTypes = stubsCpg.identifier.nameExact("ghost").typeFullName.l.distinct
      ghostTypes.foreach { t =>
          withClue(s"ghost type $t must not be a real TYPE_DECL: ") {
              stubsCpg.typeDecl.fullNameExact(t).l shouldBe empty
          }
      }

    "keep an If that is not imports-only truncated away" in:
      // The TYPE_CHECKING guard is kept only when it holds nothing but imports. A block that
      // also runs statements is library internals, and keeping it would resurrect bodies the
      // signature mode exists to omit: the second guard's assignment must contribute nothing.
      val moduleLocals =
          stubsCpg.method.fullNameExact("flask.globals").local.name.l
      moduleLocals should not contain "os_sep"

    "keep annotation names no TYPE_DECL backs exactly as they were" in:
      // `site: NotImported` in flask/globals.py: `NotImported` resolves to nothing in the
      // graph, so the member must keep the bare name rather than a invented full name.
      val siteType =
          stubsCpg.typeDecl.fullNameExact("flask.globals").member.nameExact(
            "site"
          ).typeFullName.l
      siteType.foreach(_ should not startWith "flask/")

    "keep an alias return the target cannot resolve as the bare annotation" in:
      // `wobble() -> Widget`: `Widget` is neither imported nor defined in flask/helpers.py,
      // so the alias return must stay the bare name - the alias must not look more resolved
      // than its own module.
      val wobbleReturns =
          stubsCpg.method
              .fullNameExact("flask.wobble", "flask.wobble")
              .methodReturn
              .typeFullName
              .l
              .distinct
      wobbleReturns shouldBe List("Widget")

  "python-deps=none - the same code without ingestion" should:

    "gain none of the dependency types" in:
      val cpg = code(userApp, "app.py").withProjectSetup(writeFakeVenv)
      // Nothing ingested: the full names above must not exist anywhere in the graph.
      cpg.typeDecl.fullNameExact("flask.app.Flask").l shouldBe empty
      cpg.typeDecl.fullNameExact("flask.app.Config").l shouldBe empty
      cpg.identifier.nameExact("request").typeFullName.l.distinct.foreach(_ should not equal
          "flask.app.Flask")
      cpg.identifier.nameExact("cfg").typeFullName.l.distinct.foreach(_ should not equal
          "flask.app.Config")
      cpg.identifier.nameExact("r").typeFullName.l.distinct.foreach(_ should not equal
          "flask.helpers.Response")
end PythonDependencyTypeTests
