package io.appthreat.pysrc2cpg

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Task 09 section B: the module-name rules that make dotted names unambiguous, asserted against
  * CPython's own import semantics (oracle: 3.14.6, `importlib.util.find_spec` - a directory
  * containing `__init__.py` is found by the path finder BEFORE same-named module files, so the
  * package wins and the shadowed file is unimportable).
  */
class PythonModuleNameTests extends AnyWordSpec with Matchers:

  private def mod(files: Set[String], f: String) = PythonModuleName.moduleFor(files, f)

  "moduleFor" should {

      "map plain modules and packages to dotted names" in {
          mod(Set("helpers.py"), "helpers.py") shouldBe Some("helpers")
          mod(Set("flask/__init__.py", "flask/app.py"), "flask/app.py") shouldBe Some("flask.app")
          mod(Set("flask/__init__.py", "flask/app.py"), "flask/__init__.py") shouldBe Some("flask")
      }

      "treat .pyi as the same module as .py (a module shipping both spellings is ONE module)" in {
          // Pre-fix: anything not ending `.py` returned None, so every typeshed stub and every
          // stub-shipping distribution resolved to no module at all.
          mod(Set("mod.pyi"), "mod.pyi") shouldBe Some("mod")
          mod(Set("pkg/__init__.pyi", "pkg/a.pyi"), "pkg/a.pyi") shouldBe Some("pkg.a")
          mod(Set("mod.py", "mod.pyi"), "mod.pyi") shouldBe Some("mod")
          mod(Set("mod.py", "mod.pyi"), "mod.py") shouldBe Some("mod")
      }

      "let the regular package win over a same-named module file (CPython precedence)" in {
          val collision = Set("pkg/__init__.py", "pkg/mod.py", "pkg/mod/__init__.py")
          mod(collision, "pkg/mod/__init__.py") shouldBe Some("pkg.mod")
          // The shadowed module file must NOT merge into the package's name: it gets a
          // deterministic, disclosed, non-colliding name instead.
          mod(collision, "pkg/mod.py") shouldBe Some("pkg.mod.__shadowed__")
      }

      "leave non-source names unresolved" in {
          mod(Set("requirements.txt"), "requirements.txt") shouldBe None
          mod(Set("N/A"), "N/A") shouldBe None
      }

      "resolve package-less files as PEP 420 namespace modules" in {
          mod(Set("flask/sansio/app.py"), "flask/sansio/app.py") shouldBe Some("flask.sansio.app")
      }
  }

  "dottedFromFullName" should {

      "map the module scope segment to nothing and keep the qualname" in {
          val m = PythonModuleName.dottedFromFullName(
            _ => Some("flask.app"),
            "flask/app.py:<module>.Flask.route"
          )
          m shouldBe Some("flask.app.Flask.route")
      }

      "resolve .pyi file parts too" in {
          val m = PythonModuleName.dottedFromFullName(
            _ => Some("subprocess"),
            "subprocess.pyi:<module>.run"
          )
          m shouldBe Some("subprocess.run")
      }

      "yield None for names without a file prefix" in {
          PythonModuleName.dottedFromFullName(_ => Some("x"), "__builtin.print") shouldBe None
      }
  }
end PythonModuleNameTests
