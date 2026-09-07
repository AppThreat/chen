package io.appthreat.pysrc2cpg

import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Paths}

/** Task 12 Part A against REAL published distributions - the `flask-3.0.3` wheel and the
  * `itsdangerous-2.2.0` sdist from the corpus, i.e. the exact input of the 0.3 archive gap.
  *
  * These assert the ingested CONTENT - module counts, dotted names, externality, purls - which an
  * atom's byte size can only stand in for. A size distinguishes "extracted something" from
  * "extracted nothing" and nothing finer: it moves for unrelated reasons, and when it moves nobody
  * can tell whether the graph got better or worse. The `verify-12.sh` archive gate keeps a size
  * floor as a crude tripwire; the real claims live here.
  *
  * The fixtures are third-party archives that do not belong in the repo, so the whole suite is
  * registered only when the corpus is present - absent it, there are no tests rather than
  * cancellations.
  */
class PythonRealArchiveIngestionTests extends AnyWordSpec with Matchers:

  private val packages =
      Paths.get(System.getProperty("user.home"), "sandbox", "py-corpus", "packages")

  /** Whether the corpus archives are on this machine. Checked at REGISTRATION time, so a machine
    * without them runs a suite with no tests rather than four cancellations - a cancelled test
    * reads as something gone wrong in a CI summary, and these fixtures are simply absent by design
    * on any host but a developer's.
    */
  private val corpusPresent =
      Files.isRegularFile(packages.resolve("flask-3.0.3-py3-none-any.whl"))

  private def withRepro(body: io.shiftleft.codepropertygraph.Cpg => Unit): Unit =
    val dir = Files.createTempDirectory("chen-real-archive-")
    val out = Files.createTempFile("chen-real-archive-", ".odb")
    try
      Seq("flask-3.0.3-py3-none-any.whl", "itsdangerous-2.2.0.tar.gz").foreach { name =>
          Files.copy(packages.resolve(name), dir.resolve(name))
      }
      new Py2CpgOnFileSystem().createCpg(
        Py2CpgOnFileSystemConfig()
            .withInputPath(dir.toString)
            .withOutputPath(out.toString)
      ) match
        case scala.util.Success(cpg) =>
            try body(cpg)
            finally cpg.close()
        case scala.util.Failure(e) => fail(s"createCpg failed on the 0.3 repro input: $e")
    finally
      Files.walk(dir).sorted(java.util.Comparator.reverseOrder()).forEach(_.toFile.delete())
      Files.deleteIfExists(out)
  end withRepro

  if corpusPresent then
    "the 0.3 archive gap input (a wheel and an sdist, no .py of its own)" should {

        "ingest both distributions' real layouts" in {
            withRepro { cpg =>
              val files = cpg.file.name.l
              // The wheel unpacks at the zip root, so its modules are `flask/...`.
              files.count(_.startsWith("flask/")) shouldBe 24
              // The sdist keeps the src layout its author chose - the `<pkg>-<ver>/` wrapper is
              // unwrapped, the `src/` hop is NOT (it is part of the tree, and PythonModuleName
              // strips it when computing module names).
              files.count(_.startsWith("src/itsdangerous/")) shouldBe 8
              files should contain("flask/sansio/app.py")
              files should contain("src/itsdangerous/url_safe.py")
            }
        }

        "name modules dottedly from each archive's own root" in {
            withRepro { cpg =>
              // The whole point of per-root naming: the wheel root and the sdist root have
              // disjoint namespaces, and neither anchors the other's names.
              cpg.method.fullNameExact("flask.app.Flask.run").l should not be empty
              // `URLSafeSerializerMixin`, the class the sdist actually ships in that module - the
              // dotted name is derived from the sdist's `src/` layout with the `src` hop dropped
              // exactly as PythonModuleName drops it for a project's own src tree.
              val loader = cpg.method
                  .fullNameExact("itsdangerous.url_safe.URLSafeSerializerMixin.load_payload").l
              loader should not be empty
            }
        }

        "attribute every ingested method as dependency code" in {
            withRepro { cpg =>
              // Nothing here is project code - the input carries no .py of its own - so the
              // near-miss that matters is the opposite one: not a single method may stay internal,
              // or reachables would report library findings as the project's.
              val internal = cpg.method.filterNot(_.isExternal).fullName.l
              internal shouldBe empty
            }
        }

        "state each distribution's identity as a normalised purl, with no SBOM present" in {
            withRepro { cpg =>
              val purls = cpg.method.tag.name.l.filter(_.startsWith("pkg:pypi/")).distinct.sorted
              purls shouldBe List("pkg:pypi/flask@3.0.3", "pkg:pypi/itsdangerous@2.2.0")
              // Read off the wheel's RECORD/METADATA and the sdist's PKG-INFO respectively - the
              // corpus has no bom.json, so an SBOM-driven path would tag nothing at all.
              val runTags = cpg.method.fullNameExact("flask.app.Flask.run").head.tag.name.l
              runTags should contain("pkg:pypi/flask@3.0.3")
            }
        }
    }
  end if
end PythonRealArchiveIngestionTests
