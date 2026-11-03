package io.appthreat.c2cpg.passes

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.c2cpg.astcreation.Defines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The header that declares what a file reads or calls, on the node that does the reading: a
  * library's global, enumerator, macro, method, constructor and struct member against the project's
  * own same-named things in another file. The library header sits outside the analysed input,
  * reached through `--include-path`, so no METHOD or TYPE_DECL of the graph is built from it.
  */
class DeclaringHeaderTagTests extends AnyWordSpec with Matchers:

  private val libHeader =
      """#ifndef LIB_H
        |#define LIB_H
        |#define LIB_VERSION 3
        |#define LIB_MAX(a, b) ((a) > (b) ? (a) : (b))
        |#define LIB_WRAP(x) lib_func(x)
        |#define LIB_INNER(x) ((x) + 1)
        |#define LIB_OUTER(x) LIB_INNER(x) * 2
        |extern int lib_global;
        |enum lib_errno { LIB_OK = 0, LIB_BAD = 1 };
        |struct lib_struct { int field_a; int field_b; };
        |int lib_func(int x);
        |class LibClass {
        |public:
        |  LibClass(int v);
        |  int value() const;
        |  int mem;
        |};
        |#endif
        |""".stripMargin

  private val projHeader =
      """#ifndef PROJ_H
        |#define PROJ_H
        |#define PROJ_DOUBLE(x) ((x) * 2)
        |#define PROJ_CALL(x) lib_func(x)
        |enum proj_enum { PROJ_ONE = 1 };
        |extern int proj_global;
        |struct proj_struct { int field_a; };
        |int proj_helper(int x);
        |class ProjClass { public: ProjClass(int v); int value() const; int mem; };
        |#endif
        |""".stripMargin

  private val mainC =
      """#include "libdir/lib.h"
        |#include "proj.h"
        |static int use_all(int a, int b) {
        |  int v = LIB_VERSION;
        |  int m = LIB_MAX(a, b);
        |  int w = LIB_WRAP(a);
        |  int d = PROJ_DOUBLE(a);
        |  int g = lib_global;
        |  int e = LIB_BAD;
        |  int p = PROJ_ONE;
        |  int pg = proj_global;
        |  struct lib_struct ls;
        |  ls.field_a = 1;
        |  struct proj_struct ps;
        |  ps.field_a = 2;
        |  int (*fp)(int) = lib_func;
        |  int c = lib_func(v + m + w + d);
        |  int h = proj_helper(g + e + p + pg + ls.field_a + ps.field_a + fp(1));
        |  int n = LIB_OUTER(a);
        |  int q = LIB_MAX(a, LIB_VERSION);
        |  int r = PROJ_CALL(a);
        |  int s = PROJ_DOUBLE(LIB_MAX(a, 1));
        |  return h + n + q + r + s;
        |}
        |int main(void) { return use_all(1, 2); }
        |""".stripMargin

  private val klassCpp =
      """#include "libdir/lib.h"
        |#include "proj.h"
        |int use_cpp(int x) {
        |  LibClass obj(x);
        |  ProjClass pobj(x);
        |  LibClass *p = &obj;
        |  int v = obj.value();
        |  int w = p->mem;
        |  LibClass *heap = new LibClass(v);
        |  return v + w + heap->value() + pobj.value() + pobj.mem;
        |}
        |""".stripMargin

  // the run's roots, set by withScopedRun so each assertion can name the exact paths
  private var libHeaderPath: String  = _
  private var projHeaderPath: String = _

  private def withScopedRun[T](f: Cpg => T): T =
    val root = File.newTemporaryDirectory("hdrdecl")
    try
      (root / "externlib" / "libdir").createDirectories()
      (root / "proj").createDirectories()
      (root / "externlib" / "libdir" / "lib.h").write(libHeader)
      (root / "proj" / "proj.h").write(projHeader)
      (root / "proj" / "main.c").write(mainC)
      (root / "proj" / "klass.cpp").write(klassCpp)
      // the parser resolves real paths (macOS `/var` is `/private/var`)
      libHeaderPath = java.nio.file.Paths.get(
        (root / "externlib" / "libdir" / "lib.h").pathAsString
      ).toRealPath().toString
      projHeaderPath = java.nio.file.Paths.get(
        (root / "proj" / "proj.h").pathAsString
      ).toRealPath().toString
      val out = File.newTemporaryFile("hdrdecl", ".atom")
      out.deleteOnExit()
      val cpg = new C2Cpg().createCpg(
        Config()
            .withInputPath((root / "proj").pathAsString)
            .withOutputPath(out.pathAsString)
            .withIncludePaths(Set((root / "externlib").pathAsString))
            .withAstCache(false)
            .withFunctionBodies(true)
      ).get
      try f(cpg)
      finally cpg.close()
    finally root.delete(swallowIOExceptions = true)
    end try
  end withScopedRun

  private def refTags(cpg: Cpg, name: String): List[String] =
      cpg.identifier.nameExact(name).tag.nameExact(Defines.RefDeclaredInTag).value.l

  private def callTags(cpg: Cpg, name: String, tag: String): List[String] =
      cpg.call.nameExact(name).tag.nameExact(tag).value.l

  "a global the file only reads" should {
      "carry the library header that declares it" in withScopedRun { cpg =>
          refTags(cpg, "lib_global") should contain only libHeaderPath
      }
      "carry the project header for the project's own global, never the library's" in
          withScopedRun { cpg =>
              refTags(cpg, "proj_global") should contain only projHeaderPath
          }
  }

  "an enumerator the file reads" should {
      "carry the library header that enumerates it, folded as it is" in withScopedRun { cpg =>
          refTags(cpg, "LIB_BAD") should contain only libHeaderPath
      }
      "carry the project header for the project's own enumerator" in withScopedRun { cpg =>
          refTags(cpg, "PROJ_ONE") should contain only projHeaderPath
      }
  }

  "a function named as a value" should {
      "carry the library header that declares it" in withScopedRun { cpg =>
          cpg.methodRef.methodFullName("lib_func").tag
              .nameExact(Defines.RefDeclaredInTag).value.l should contain only libHeaderPath
      }
  }

  "a macro defined in two headers" should {
      "name the definition in effect where it is nested" in {
          val root = File.newTemporaryDirectory("hdrtwice")
          try
            (root / "externlib").createDirectories()
            (root / "proj").createDirectories()
            (root / "externlib" / "first.h").write("#define VAL 1\n")
            (root / "externlib" / "second.h").write(
              "#undef VAL\n#define VAL 2\n#define ADD(x) ((x) + VAL)\n"
            )
            (root / "proj" / "main.c").write(
              "#include \"first.h\"\n#include \"second.h\"\nint r(void) { return ADD(1); }\n"
            )
            val second = java.nio.file.Paths.get((root / "externlib" / "second.h").pathAsString)
                .toRealPath().toString
            val out = File.newTemporaryFile("hdrtwice", ".atom")
            out.deleteOnExit()
            val cpg = new C2Cpg().createCpg(
              Config()
                  .withInputPath((root / "proj").pathAsString)
                  .withOutputPath(out.pathAsString)
                  .withIncludePaths(Set((root / "externlib").pathAsString))
                  .withAstCache(false)
                  .withFunctionBodies(true)
            ).get
            try callTags(cpg, "ADD", Defines.NestedMacroTag) shouldBe List(s"VAL@$second")
            finally cpg.close()
          finally root.delete(swallowIOExceptions = true)
          end try
      }
  }

  "a macro invocation" should {
      "name the macros nested in its arguments and its definition" in withScopedRun { cpg =>
        // PROJ_DOUBLE(LIB_MAX(a, 1)): an argument that is a macro's name names that macro
        callTags(cpg, "PROJ_DOUBLE", Defines.NestedMacroTag) should contain(
          s"LIB_MAX@$libHeaderPath"
        )
        // LIB_OUTER's definition invokes LIB_INNER
        callTags(cpg, "LIB_OUTER", Defines.NestedMacroTag) should contain(
          s"LIB_INNER@$libHeaderPath"
        )
        // an object-like macro as an argument names it too
        callTags(cpg, "LIB_MAX", Defines.NestedMacroTag) should contain(
          s"LIB_VERSION@$libHeaderPath"
        )
      }
      "name no macro for arguments that spell none" in withScopedRun { cpg =>
        // the PROJ_DOUBLE(a) invocation at line 7 has plain arguments
        cpg.call.nameExact("PROJ_DOUBLE").lineNumber(7).l should have size 1
        cpg.call.nameExact("PROJ_DOUBLE").lineNumber(7).tag.nameExact(Defines.NestedMacroTag).l shouldBe empty
      }
      "not name the invocation's own macro" in withScopedRun { cpg =>
          callTags(cpg, "LIB_MAX", Defines.NestedMacroTag) should not contain
              s"LIB_MAX@$libHeaderPath"
      }
  }

  "a member call through an object of a library class" should {
      "carry the library header that declares the method" in withScopedRun { cpg =>
          cpg.call.nameExact("value").methodFullName("LibClass.*").tag
              .nameExact(Defines.CalleeDeclaredInTag).value.l should contain only libHeaderPath
      }
      "carry the project header for the project class's same-named method" in withScopedRun { cpg =>
          cpg.call.nameExact("value").methodFullName("ProjClass.*").tag
              .nameExact(Defines.CalleeDeclaredInTag).value.l should contain only projHeaderPath
      }
  }

  "a constructor of a library class" should {
      "say what it constructs and where the class is declared" in withScopedRun { cpg =>
        val ctor = cpg.call.nameExact("LibClass").l
        ctor should have size 1
        ctor.head.tag.nameExact(Defines.CalleeDeclaredInTag).value.l should contain only
            libHeaderPath
        ctor.head.tag.nameExact(Defines.ConstructsTypeTag).value.l should contain only "LibClass"
      }
      "never name the library's header for the project's own class" in withScopedRun { cpg =>
          // the call is linked to the project's own METHOD; whatever header it names is the
          // project's, never the library's
          cpg.call.nameExact("ProjClass").tag
              .nameExact(Defines.CalleeDeclaredInTag).value.l should not contain libHeaderPath
      }
  }

  "a `new` of a library class" should {
      "name the class's header and the constructed type on the allocation" in withScopedRun { cpg =>
        val alloc = cpg.call.nameExact("<operator>.new").l
        alloc should have size 1
        alloc.head.tag.nameExact(Defines.CalleeDeclaredInTag).value.l should contain only
            libHeaderPath
        alloc.head.tag.nameExact(Defines.ConstructsTypeTag).value.l should contain only "LibClass"
      }
  }

  "a member access through a library struct" should {
      "carry the library header that defines the struct" in withScopedRun { cpg =>
        // ls.field_a: the receiver's type is the library's struct
        val access = cpg.call
            .nameExact("<operator>.fieldAccess", "<operator>.indirectFieldAccess")
            .where(_.argument.isFieldIdentifier.canonicalName("field_a"))
            .where(_.argument.isIdentifier.typeFullName("lib_struct"))
            .l
        access should not be empty
        access.flatMap(_.tag.nameExact(Defines.TypeDeclaredInTag).value.l) should contain only
            libHeaderPath
      }
      "carry the project header for the project's same-named member" in withScopedRun { cpg =>
        val access = cpg.call
            .nameExact("<operator>.fieldAccess", "<operator>.indirectFieldAccess")
            .where(_.argument.isFieldIdentifier.canonicalName("field_a"))
            .where(_.argument.isIdentifier.typeFullName("proj_struct"))
            .l
        access should not be empty
        access.flatMap(_.tag.nameExact(Defines.TypeDeclaredInTag).value.l) should contain only
            projHeaderPath
      }
  }
end DeclaringHeaderTagTests
