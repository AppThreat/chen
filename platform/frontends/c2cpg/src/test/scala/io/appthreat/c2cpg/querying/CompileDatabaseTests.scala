package io.appthreat.c2cpg.querying

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** A compilation database decides which files are parsed and how: each translation unit with its
  * own macros, include path and language.
  */
class CompileDatabaseTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private def database(entries: String*): String = entries.mkString("[", ",", "]")

  private def entry(file: String, command: String): String =
      s"""{"directory": ".", "file": "$file", "command": "$command"}"""

  "translation units compiled with different macros" should {
      val cpg = code(
        """
          |#ifdef FAST
          |int fastPath(int n) { return n * 2; }
          |#else
          |int slowPath(int n) { return n + n; }
          |#endif
          |""".stripMargin,
        "fast.c"
      ).moreCode(
        """
          |#if LEVEL > 1
          |int levelTwo(void) { return 2; }
          |#endif
          |""".stripMargin,
        "level.c"
      ).moreCode(
        """
          |#ifdef FAST
          |int notCompiled(void) { return 0; }
          |#endif
          |""".stripMargin,
        "unused.c"
      ).moreCode(
        database(
          entry("fast.c", "cc -DFAST -c fast.c"),
          entry("level.c", """cc -D LEVEL=2 -c \"level.c\"""")
        ),
        "compile_commands.json"
      ).withConfig(Config().withCompileCommands("compile_commands.json"))

      "parse each unit with its own definitions" in {
          cpg.method.nameExact("fastPath").l should have size 1
          cpg.method.nameExact("slowPath").l shouldBe empty
          cpg.method.nameExact("levelTwo").l should have size 1
      }

      "parse only the units the database compiles" in {
          cpg.file.name.l.filter(_.endsWith(".c")).sorted shouldBe List("fast.c", "level.c")
          cpg.method.nameExact("notCompiled").l shouldBe empty
      }
  }

  "a header with C++ syntax" should {
      val cpg = code(
        """
          |#include "shape.h"
          |double area(const Shape &s) { return s.area(); }
          |""".stripMargin,
        "main.cpp"
      ).moreCode(
        """
          |#pragma once
          |namespace geo {}
          |class Shape {
          |public:
          |  virtual ~Shape() {}
          |  virtual double area() const { return 0; }
          |};
          |""".stripMargin,
        "shape.h"
      ).moreCode("int plain(int x) { return x; }", "plain.c")
          .moreCode("int helper(int x);", "helper.h")
          .moreCode("#include \"helper.h\"\nint helper(int x) { return x; }", "helper.c")

      "be parsed as C++ when a C++ file includes it" in {
          val List(area) = cpg.method.nameExact("area").filter(_.filename == "shape.h").l
          area.fullName shouldBe "Shape.area:double()"
          cpg.typeDecl.nameExact("Shape").filter(_.filename == "shape.h").l should have size 1
      }

      "leave a header only C files include as C" in {
          cpg.method.nameExact("helper").filename.toSetMutable shouldBe Set("helper.h", "helper.c")
      }
  }

  "a database entry with an MSVC command" should {
      val cpg = code(
        """
          |#ifdef _WIN32
          |int onWindows(void) { return 1; }
          |#endif
          |#ifdef FROM_DB
          |int fromDatabase(void) { return 1; }
          |#endif
          |""".stripMargin,
        "win.c"
      ).moreCode(
        database(
          s"""{"directory": ".", "file": "win.c", "arguments": ["cl.exe", "/DFROM_DB", "/c", "win.c"]}"""
        ),
        "compile_commands.json"
      ).withConfig(Config().withCompileCommands("compile_commands.json"))

      "use the macros MSVC predefines and the entry's own" in {
          cpg.method.nameExact("onWindows").l should have size 1
          cpg.method.nameExact("fromDatabase").l should have size 1
      }
  }

  "--compile-commands-only" should {
      val cpg = code("int unit(void) { return 0; }", "unit.c")
          .moreCode(
            "int declaredOnly(void);\nstatic inline int inHeader(void) { return 1; }",
            "api.h"
          )
          .moreCode(database(entry("unit.c", "cc -c unit.c")), "compile_commands.json")
          .withConfig(Config().withCompileCommands(".").withCompileCommandsOnly(true))

      "parse no header on its own" in {
          cpg.method.nameExact("unit").l should have size 1
          cpg.method.nameExact("inHeader").l shouldBe empty
      }
  }
end CompileDatabaseTests
