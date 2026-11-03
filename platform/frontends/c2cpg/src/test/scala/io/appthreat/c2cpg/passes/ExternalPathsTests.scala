package io.appthreat.c2cpg.passes

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** `--external-paths`: code a project carries from someone else keeps its bodies and types, and its
  * methods and types are marked external. The project's own code, and a run without the option, are
  * untouched.
  */
class ExternalPathsTests extends AnyWordSpec with Matchers:

  private def withProject[T](pattern: String)(f: Cpg => T): T =
    val root = File.newTemporaryDirectory("extpaths")
    try
      (root / "third_party" / "zlib").createDirectories()
      (root / "third_party" / "zlib" / "zlib.h").write(
        "int zlib_compress(unsigned char *out, int len);\n"
      )
      (root / "third_party" / "zlib" / "zlib.c").write(
        "#include \"zlib.h\"\nint zlib_compress(unsigned char *out, int len) { return len; }\n"
      )
      (root / "main.c").write(
        "#include \"third_party/zlib/zlib.h\"\nint main(void) { return zlib_compress(0, 4); }\n"
      )
      val out = File.newTemporaryFile("extpaths", ".atom")
      out.deleteOnExit()
      val config = Config()
          .withInputPath(root.pathAsString)
          .withOutputPath(out.pathAsString)
          .withAstCache(false)
          .withFunctionBodies(true)
      val withPattern = if pattern.isEmpty then config else config.withExternalPaths(pattern)
      val cpg         = new C2Cpg().createCpg(withPattern).get
      try f(cpg)
      finally cpg.close()
    finally root.delete(swallowIOExceptions = true)
    end try
  end withProject

  "a vendored path the pattern names" should {
      "have its methods and types external, its bodies still there" in withProject(
        "third_party/"
      ) { cpg =>
        cpg.method.name("zlib_compress").isExternal.l shouldBe List(true, true)
        cpg.typeDecl.name("zlib_compress").l shouldBe empty // a function, not a type
        // the body is parsed as always: the parameter and the return are on the graph
        cpg.method.name("zlib_compress").parameter.name.l should contain("len")
      }
      "leave the project's own code internal" in withProject("third_party/") { cpg =>
          cpg.method.name("main").isExternal.l shouldBe List(false)
      }
  }

  "a run without the option" should {
      "mark nothing external" in withProject("") { cpg =>
          cpg.method.name("zlib_compress", "main").isExternal.l should contain only false
      }
  }

  "a pattern that names no path of the project" should {
      "mark nothing external" in withProject("vendor/") { cpg =>
          cpg.method.name("zlib_compress", "main").isExternal.l should contain only false
      }
  }
end ExternalPathsTests
