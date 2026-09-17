package io.appthreat.pysrc2cpg

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The python AST cache honours `cacheDir` the way the C/C++ and PHP frontends do.
  *
  * The default cache location is `<input>/.chen`, i.e. INSIDE the analysed tree. A caller analysing
  * a tree it must not write into - a checked-in test fixture, a read-only checkout - redirects the
  * fragments with `withCacheDir`; until this existed the python frontend had no override at all and
  * always littered the input directory.
  */
class Py2CpgCacheDirTests extends AnyWordSpec with Matchers:

  private def analyseInto(input: File, out: File, cacheDir: Option[String]): Unit =
    val base = Py2CpgOnFileSystemConfig()
        .withInputPath(input.pathAsString)
        .withOutputPath(out.pathAsString)
    val config = cacheDir.map(base.withCacheDir).getOrElse(base)
    new Py2CpgOnFileSystem().createCpg(config).get.close()

  "Py2CpgOnFileSystem with a configured cacheDir" should {

      "write AST fragments under the configured directory, not <input>/.chen" in {
          File.usingTemporaryDirectory("chen-cachedir-in-") { input =>
              File.usingTemporaryDirectory("chen-cachedir-out-") { cacheDir =>
                (input / "app.py").write("def main():\n    return 1\n")
                val out = File.newTemporaryFile("cachedir-", ".odb")
                try
                  // The configured path IS the cache root: cache files (.ast entries, or
                  // .frag fragments in the fragment mode) land directly inside it.
                  analyseInto(input, out, Some(cacheDir.pathAsString))
                  cacheDir.list.nonEmpty shouldBe true
                  // Nothing was written into the analysed tree.
                  (input / ".chen").exists shouldBe false
                finally out.delete(swallowIOExceptions = true)
              }
          }
      }

      "default to <input>/.chen when no cacheDir is configured" in {
          File.usingTemporaryDirectory("chen-cachedir-default-") { input =>
            (input / "app.py").write("def main():\n    return 2\n")
            val out = File.newTemporaryFile("cachedir-default-", ".odb")
            try
              analyseInto(input, out, None)
              (input / ".chen").exists shouldBe true
            finally out.delete(swallowIOExceptions = true)
          }
      }
  }
end Py2CpgCacheDirTests
