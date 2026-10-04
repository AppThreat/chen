package io.appthreat.edg2atom.passes

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.edg2atom.Edg2Atom
import io.appthreat.edg2atom.parser.EdgaRunner
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class EdgAstCreationPassTests extends AnyWordSpec with Matchers:

  private val edga = EdgaRunner.locate()

  private def project(files: (String, String)*)(test: File => Unit): Unit =
      File.usingTemporaryDirectory("edg2atom") { dir =>
        files.foreach { (name, text) =>
            (dir / name).createIfNotExists(createParents = true).writeText(text)
        }
        test(dir)
      }

  private def graph(
    dir: File,
    fallback: Boolean = false,
    cache: Boolean = false
  )(check: Cpg => Unit): Unit =
    val out = File.newTemporaryFile("edg2atom", ".atom")
    val config = Config().withInputPath(dir.pathAsString).withOutputPath(out.pathAsString)
        .withFunctionBodies(true).withAstCache(cache)
    val cpg = new Edg2Atom(fallback).createCpg(config).get
    try check(cpg)
    finally
      cpg.close()
      out.delete(swallowIOExceptions = true)

  /** Runs `test` with edga replaced by a program that fails every unit. */
  private def withFailingEdga(dir: File)(test: => Unit): Unit =
    val fake = dir / "fake-edga"
    // the same build, by its identity, that exports nothing
    fake.writeText(
      s"#!/bin/sh\nif [ \"$$1\" = \"--edga-version\" ]; then exec ${edga.get} --edga-version; fi\nexit 4\n"
    )
    fake.toJava.setExecutable(true)
    val saved = sys.props.get("edga.path")
    sys.props("edga.path") = fake.pathAsString
    try test
    finally saved match
          case Some(p) => sys.props("edga.path") = p
          case None    => sys.props.remove("edga.path")

  private val shared = "shared.h" -> "static inline int twice(int x) { return 2 * x; }\n"
  private val first = "a.c" -> "#include \"shared.h\"\nint first(int x) { return twice(x); }\n"
  private val second =
      "b.c" -> "#include \"shared.h\"\nint second(int x) { return twice(x) + 1; }\n"
  private val broken = "c.c" -> "#include \"missing.h\"\nint third(void) { return 3; }\n"

  "a project header" should {
      "be written once, with the first unit that includes it" in {
          assume(edga.isDefined, "edga is not installed")
          project(shared, first, second) { dir =>
              graph(dir) { cpg =>
                cpg.method.nameExact("twice").filter(_.block.astChildren.nonEmpty).size shouldBe 1
                cpg.method.nameExact("twice").filename.l.distinct shouldBe List("shared.h")
              }
          }
      }
  }

  "a template instance from a project header" should {
      val header = "clamp.hpp" ->
          """template <typename T> T clamp(T v, T lo, T hi) { return v < lo ? lo : (v > hi ? hi : v); }
          |template <typename T> struct Box { T item; T get() const { return item; } };
          |""".stripMargin
      val ints =
          "a.cpp" -> "#include \"clamp.hpp\"\nint a(int v) { Box<int> b{v}; return clamp(b.get(), 0, 9); }\n"
      val shorts =
          "b.cpp" -> "#include \"clamp.hpp\"\nshort b(short v) { Box<short> s{v}; return clamp<short>(s.get(), 0, 9) + clamp(1, 0, 9); }\n"

      "be in the graph once, whichever units use it" in {
          assume(edga.isDefined, "edga is not installed")
          project(header, ints, shorts) { dir =>
              graph(dir) { cpg =>
                val clamps = cpg.method.nameExact("clamp").filter(_.block.astChildren.nonEmpty).l
                clamps.map(_.fullName).sorted shouldBe List(
                  "clamp:int(int,int,int)",
                  "clamp:short(short,short,short)"
                )
                cpg.method.nameExact("get").filter(_.block.astChildren.nonEmpty).fullName.l.sorted shouldBe
                    List("Box<int>.get:int()", "Box<short>.get:short()")
                cpg.typeDecl.isExternal(false).fullName("Box<.*").fullName.l.sorted shouldBe List(
                  "Box<int>",
                  "Box<short>"
                )
                clamps.map(_.filename).distinct shouldBe List("clamp.hpp")
              }
          }
      }
  }

  "a template instance with a lambda, written by two units" should {
      val header = "find.hpp" ->
          """template <class K> int find_or_insert(K key) {
          |  int index;
          |  bool inserted;
          |  [&]() {
          |    index = static_cast<int>(key);
          |    inserted = key != 0;
          |  }();
          |  return inserted ? index : -1;
          |}
          |""".stripMargin
      // a lambda of its own first, so the units number the instance's lambda differently
      val first = "a.cpp" ->
          "#include \"find.hpp\"\nint a(long k) { auto f = [](int x) { return x; }; return f(1) + find_or_insert(k); }\n"
      val second = "b.cpp" -> "#include \"find.hpp\"\nint b(long k) { return find_or_insert(k); }\n"

      "keep the lambda the copy kept refers to" in {
          assume(edga.isDefined, "edga is not installed")
          project(header, first, second) { dir =>
              graph(dir) { cpg =>
                val outer =
                    cpg.method.nameExact("find_or_insert").filter(_.block.astChildren.nonEmpty).l
                outer.size shouldBe 1
                val lambdas = outer.head.ast.isMethodRef.methodFullName.l
                lambdas.size shouldBe 1
                cpg.method.fullNameExact(lambdas.head).ast.isIdentifier.name.l should contain(
                  "inserted"
                )
              }
          }
      }
  }

  "a unit edga cannot export" should {
      "be left out without the fallback" in {
          assume(edga.isDefined, "edga is not installed")
          project(first, shared, broken) { dir =>
              graph(dir) { cpg =>
                cpg.method.nameExact("first").size shouldBe 1
                cpg.method.nameExact("third") shouldBe empty
              }
          }
      }

      "be parsed by the CDT frontend with it, and say so" in {
          assume(edga.isDefined, "edga is not installed")
          project(first, shared, broken) { dir =>
              graph(dir, fallback = true) { cpg =>
                cpg.method.nameExact("third").size shouldBe 1
                def frontendOf(name: String) =
                    cpg.file.nameExact(name).tag.nameExact(FrontendTagPass.Tag).value.l
                frontendOf("a.c") shouldBe List(FrontendTagPass.Edg)
                frontendOf("shared.h") shouldBe List(FrontendTagPass.Edg)
                frontendOf("c.c") shouldBe List(FrontendTagPass.Cdt)
              }
          }
      }
  }

  "the AST cache" should {
      "replay a unit's AST while neither it nor its headers change" in {
          assume(edga.isDefined, "edga is not installed")
          project(shared, first) { dir =>
            graph(dir, cache = true)(cpg => cpg.method.nameExact("first").size shouldBe 1)
            withFailingEdga(dir) {
                graph(dir, cache = true)(cpg => cpg.method.nameExact("first").size shouldBe 1)
                // a header the unit includes is part of the key
                (dir / "shared.h").appendLine("static inline int thrice(int x) { return 3 * x; }")
                graph(dir, cache = true)(cpg => cpg.method.nameExact("first") shouldBe empty)
            }
          }
      }

      "not replay an AST another edga build exported" in {
          assume(edga.isDefined, "edga is not installed")
          project(shared, first) { dir =>
            graph(dir, cache = true)(cpg => cpg.method.nameExact("first").size shouldBe 1)
            // a build that names itself differently, and exports nothing
            val other = dir / "other-edga"
            other.writeText(
              "#!/bin/sh\nif [ \"$1\" = \"--edga-version\" ]; then echo edga-other; exit 0; fi\nexit 4\n"
            )
            other.toJava.setExecutable(true)
            val saved = sys.props.get("edga.path")
            sys.props("edga.path") = other.pathAsString
            try graph(dir, cache = true)(cpg => cpg.method.nameExact("first") shouldBe empty)
            finally saved match
                  case Some(p) => sys.props("edga.path") = p
                  case None    => sys.props.remove("edga.path")
          }
      }
  }

  "a missing edga" should {
      "leave the whole project to the CDT frontend with the fallback" in {
          project(first, shared) { dir =>
            val saved = sys.props.get("edga.path")
            sys.props("edga.path") = (dir / "no-such-edga").pathAsString
            try
                if EdgaRunner.locate().isEmpty then
                  graph(dir, fallback = true) { cpg =>
                    cpg.method.nameExact("first").size shouldBe 1
                    cpg.file.nameExact("a.c").tag.nameExact(FrontendTagPass.Tag).value.l shouldBe List(
                      FrontendTagPass.Cdt
                    )
                  }
            finally saved match
                  case Some(p) => sys.props("edga.path") = p
                  case None    => sys.props.remove("edga.path")
          }
      }
  }
end EdgAstCreationPassTests
