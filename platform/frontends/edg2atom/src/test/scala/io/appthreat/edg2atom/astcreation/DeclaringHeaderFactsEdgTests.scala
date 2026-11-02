package io.appthreat.edg2atom.astcreation

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.Defines
import io.appthreat.edg2atom.Edg2Atom
import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** The same declaring-header facts the CDT frontend tags, read from what edga exports: the include
  * directives of the primary file, a global and an enumerator the code reads, a macro invocation
  * the front end folded away, one nested in another's expansion, a library method, constructor,
  * `new` and struct member. The library header sits outside the analysed input, reached through
  * `--include-path`.
  */
class DeclaringHeaderFactsEdgTests extends EdgCodeToCpgSuite(".c"):

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
        |#endif
        |""".stripMargin

  private val projHeader =
      """#ifndef PROJ_H
        |#define PROJ_H
        |#define PROJ_DOUBLE(x) ((x) * 2)
        |#define PROJ_CALL(x) lib_func(x)
        |enum proj_enum { PROJ_ONE = 1 };
        |extern int proj_global;
        |int proj_helper(int x);
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
        |  int (*fp)(int) = lib_func;
        |  int c = lib_func(v + m + w + d);
        |  int h = proj_helper(g + e + p + pg + ls.field_a + fp(1));
        |  int n = LIB_OUTER(a);
        |  int q = LIB_MAX(a, LIB_VERSION);
        |  int r = PROJ_CALL(a);
        |  int s = PROJ_DOUBLE(LIB_MAX(a, 1));
        |  return h + n + q + r + s;
        |}
        |int main(void) { return use_all(1, 2); }
        |""".stripMargin

  private val libCppHeader =
      """#ifndef LIBCPP_H
        |#define LIBCPP_H
        |class LibClass {
        |public:
        |  LibClass(int v);
        |  int value() const;
        |  int mem;
        |};
        |#endif
        |""".stripMargin

  private val klassCpp =
      """#include <cstdio>
        |#include "libdir/libhpp.h"
        |int use_cpp(int x) {
        |  LibClass obj(x);
        |  LibClass *p = &obj;
        |  int v = obj.value();
        |  int w = p->mem;
        |  LibClass *heap = new LibClass(v);
        |  return v + w + heap->value();
        |}
        |""".stripMargin

  private var libHeaderPath: String    = _
  private var libCppHeaderPath: String = _
  private var projHeaderPath: String   = _

  private def withScopedRun[T](cpp: Boolean)(f: Cpg => T): T =
    requireEdga()
    val root = File.newTemporaryDirectory("edghdr")
    try
      (root / "externlib" / "libdir").createDirectories()
      (root / "proj").createDirectories()
      (root / "externlib" / "libdir" / "lib.h").write(libHeader)
      (root / "externlib" / "libdir" / "libhpp.h").write(libCppHeader)
      (root / "proj" / "proj.h").write(projHeader)
      (root / "proj" / "main.c").write(mainC)
      if cpp then (root / "proj" / "klass.cpp").write(klassCpp)
      libHeaderPath = java.nio.file.Paths
          .get((root / "externlib" / "libdir" / "lib.h").pathAsString).toRealPath().toString
      libCppHeaderPath = java.nio.file.Paths
          .get((root / "externlib" / "libdir" / "libhpp.h").pathAsString).toRealPath().toString
      projHeaderPath = java.nio.file.Paths
          .get((root / "proj" / "proj.h").pathAsString).toRealPath().toString
      val out = File.newTemporaryFile("edghdr", ".atom")
      out.deleteOnExit()
      val cpg = new Edg2Atom().createCpg(
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

  "an include directive of the primary file" should {
      "become an IMPORT tagged with the file it resolved to and its system spelling" in
          withScopedRun(cpp = false) { cpg =>
            val libImport = cpg.imports.code("#include \"libdir/lib.h\"").l
            libImport should have size 1
            libImport.head.tag.nameExact(Defines.IncludeResolvedPathTag).value.l should
                contain only libHeaderPath
            // a quoted include is not a system one
            cpg.imports.code("#include \"libdir/lib.h\"").tag
                .nameExact(Defines.IncludeSystemTag).l shouldBe empty
          }
      "mark a system include" in withScopedRun(cpp = true) { cpg =>
        val system = cpg.imports.code("#include <.*>").l
        system should not be empty
        system.head.tag.nameExact(Defines.IncludeSystemTag).value.l should contain only "true"
      }
      "not appear for the runner's own preinclude macro file" in withScopedRun(cpp = false) { cpg =>
          cpg.imports.code(".*edga-macros.*").l shouldBe empty
      }
  }

  "a global the file reads" should {
      "carry the library header that declares it" in withScopedRun(cpp = false) { cpg =>
          refTags(cpg, "lib_global") should contain only libHeaderPath
      }
      "carry the project header for the project's own global" in withScopedRun(cpp = false) { cpg =>
          refTags(cpg, "proj_global") should contain only projHeaderPath
      }
  }

  "an enumerator the front end folds" should {
      "carry the library header that enumerates it" in withScopedRun(cpp = false) { cpg =>
          refTags(cpg, "LIB_BAD") should contain only libHeaderPath
      }
      "carry the project header for the project's own enumerator" in withScopedRun(cpp = false) {
          cpg =>
              refTags(cpg, "PROJ_ONE") should contain only projHeaderPath
      }
  }

  "a function named as a value" should {
      "carry the library header that declares it" in withScopedRun(cpp = false) { cpg =>
          cpg.methodRef.methodFullName("lib_func").tag
              .nameExact(Defines.RefDeclaredInTag).value.l should contain only libHeaderPath
      }
  }

  "a macro invocation the expression tree does not carry" should {
      "still be a call at its site, named after the macro and its defining header" in
          withScopedRun(cpp = false) { cpg =>
            // line 4: `int v = LIB_VERSION;` folds to the constant 3
            val folded = cpg.call.nameExact("LIB_VERSION").lineNumber(4).l
            folded should have size 1
            folded.head.methodFullName should startWith(s"$libHeaderPath:3:")
          }
      "place a macro nested in another's definition at the outer invocation's site" in
          withScopedRun(cpp = false) { cpg =>
            // line 17: `int n = LIB_OUTER(a);` whose definition invokes LIB_INNER
            val inner = cpg.call.nameExact("LIB_INNER").l
            inner should have size 1
            inner.head.lineNumber.map(_.intValue) shouldBe Some(17)
            val outer = cpg.call.nameExact("LIB_OUTER").lineNumber(17).l
            outer should have size 1
            inner.head.columnNumber shouldBe outer.head.columnNumber
          }
      "place an object-like macro in an argument at the outer invocation's site" in
          withScopedRun(cpp = false) { cpg =>
              // line 18: `int q = LIB_MAX(a, LIB_VERSION);`
              cpg.call.nameExact("LIB_VERSION").lineNumber(18).l should have size 1
          }
  }

  "a member call, a constructor and a `new` of a library class" should {
      "carry the library header that declares the class" in withScopedRun(cpp = true) { cpg =>
        cpg.call.nameExact("value").tag.nameExact(Defines.CalleeDeclaredInTag).value.l should
            contain only libCppHeaderPath
        cpg.call.nameExact("LibClass").lineNumber(4).tag
            .nameExact(Defines.CalleeDeclaredInTag).value.l should contain only libCppHeaderPath
        cpg.call.nameExact("LibClass").lineNumber(4).tag
            .nameExact(Defines.ConstructsTypeTag).value.l should contain only "LibClass"
        val alloc = cpg.call.nameExact("<operator>.new").l
        alloc should have size 1
        alloc.head.tag.nameExact(Defines.CalleeDeclaredInTag).value.l should contain only
            libCppHeaderPath
        alloc.head.tag.nameExact(Defines.ConstructsTypeTag).value.l should contain only "LibClass"
      }
  }

  "a member access through a library struct" should {
      "carry the library header that defines the struct" in withScopedRun(cpp = true) { cpg =>
        val access = cpg.call
            .nameExact("<operator>.fieldAccess", "<operator>.indirectFieldAccess")
            .where(_.argument.isFieldIdentifier.canonicalName("mem"))
            .l
        access should not be empty
        access.flatMap(_.tag.nameExact(Defines.TypeDeclaredInTag).value.l) should contain only
            libCppHeaderPath
      }
  }
end DeclaringHeaderFactsEdgTests
