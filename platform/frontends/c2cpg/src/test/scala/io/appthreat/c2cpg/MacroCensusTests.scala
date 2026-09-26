package io.appthreat.c2cpg

import better.files.File
import _root_.io.appthreat.c2cpg.parser.MacroCensus
import _root_.io.appthreat.c2cpg.parser.MacroCensus.Tier
import _root_.io.shiftleft.codepropertygraph.Cpg
import _root_.io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class MacroCensusTests extends AnyWordSpec with Matchers:

  private def body(name: String, n: Int): String =
      (s"int $name(int x) {" :: (1 to n).map(i => s"  x += $i;").toList ::: List(
        "  return x;",
        "}"
      ))
          .mkString("\n")

  private def project(): (File, File) =
    val dir = File.newTemporaryDirectory("census")
    val ext = File.newTemporaryDirectory("census-ext")
    (dir / "src").createDirectories()
    (dir / "tests").createDirectories()
    (dir / "config.h.in").write("#undef HAVE_TEMPLATED\n")
    (ext / "sys.h").write("#define SYS_FIRST 1\n#define SYS_OPTION 1\n")
    (dir / "src" / "a.c").write(
      s"""#include <depx/api.h>
         |#define LOCAL_SWITCH 1
         |#if CONFIG_FEATURE
         |${body("feature_fn", 6)}
         |#endif
         |#ifdef HAVE_TEMPLATED
         |${body("templated_fn", 4)}
         |#endif
         |#ifdef HAVE_PROBE
         |${body("probe_fn", 4)}
         |#endif
         |#ifndef CONFIG_FALLBACK
         |${body("fallback_small", 1)}
         |#else
         |${body("fallback_big", 8)}
         |#endif
         |#ifndef ENABLE_SIMPLE
         |${body("simple_big", 8)}
         |#else
         |${body("simple_small", 1)}
         |#endif
         |#if defined(_WIN32)
         |${body("win_fn", 4)}
         |#endif
         |#ifdef DEPX_FEATURE
         |${body("depx_fn", 4)}
         |#endif
         |#ifdef SYS_OPTION
         |${body("sys_fn", 4)}
         |#endif
         |#ifdef LOCAL_SWITCH
         |${body("local_fn", 4)}
         |#endif
         |#if CONFIG_A && CONFIG_B
         |${body("mixed_fn", 4)}
         |#endif
         |/* #if CONFIG_IN_COMMENT */
         |""".stripMargin
    )
    (dir / "tests" / "t_test.c").write(
      s"""#if CONFIG_TESTONLY
         |${body("test_fn", 20)}
         |#endif
         |""".stripMargin
    )
    (dir, ext)
  end project

  "the macro census" should:
    "tier each undefined condition macro by its evidence" in:
      val (dir, ext) = project()
      try
        val report = MacroCensus.analyse(dir.path, Set(ext.path), Set.empty)
        val tiers  = report.entries.map(e => e.name -> e.tier).toMap
        tiers("CONFIG_FEATURE") shouldBe Tier.Auto
        tiers("HAVE_TEMPLATED") shouldBe Tier.Auto
        tiers("CONFIG_FALLBACK") shouldBe Tier.Auto
        tiers("HAVE_PROBE") shouldBe Tier.Suggest
        // defining it would hide the larger branch
        tiers("ENABLE_SIMPLE") shouldBe Tier.Skip
        tiers("_WIN32") shouldBe Tier.Skip
        tiers("DEPX_FEATURE") shouldBe Tier.Skip
        tiers("SYS_OPTION") shouldBe Tier.Skip
        // only ever tested together: no single-macro gain to earn
        tiers("CONFIG_A") shouldBe Tier.Skip
        // test code earns nothing
        tiers("CONFIG_TESTONLY") shouldBe Tier.Skip
        tiers.keySet should not contain "LOCAL_SWITCH"
        tiers.keySet should not contain "CONFIG_IN_COMMENT"
        report.entries.find(_.name == "CONFIG_FEATURE").map(_.gainLines) shouldBe Some(9)
      finally
        dir.delete()
        ext.delete()
      end try

    "leave a name the user defined to the user" in:
      val (dir, ext) = project()
      try
        val report = MacroCensus.analyse(dir.path, Set(ext.path), Set("CONFIG_FEATURE"))
        report.entries.map(_.name) should not contain "CONFIG_FEATURE"
      finally
        dir.delete()
        ext.delete()

    "write a macro header with the auto tier active and suggestions commented out" in:
      val (dir, ext) = project()
      try
        val header = MacroCensus.analyse(dir.path, Set(ext.path), Set.empty).toMacroHeader
        header should include("#define CONFIG_FEATURE 1")
        header should include("/* #define HAVE_PROBE 1 */")
        (header should not).include("_WIN32")
      finally
        dir.delete()
        ext.delete()

  "--auto-defines" should:
    def build(dir: File, config: Config => Config): Cpg =
      val out = File.newTemporaryFile("census", ".atom")
      out.deleteOnExit()
      new C2Cpg().createCpg(
        config(Config().withInputPath(dir.pathAsString).withOutputPath(out.pathAsString)
            .withAstCache(false))
      ).get

    "make the code behind an auto-tier macro visible, and only that" in:
      val (dir, ext) = project()
      try
        val plain = build(dir, identity)
        plain.method.name("feature_fn").l shouldBe empty
        plain.close()
        val auto = build(dir, _.withAutoDefines(true))
        auto.method.name("feature_fn").l should not be empty
        auto.method.name("fallback_big").l should not be empty
        auto.method.name("probe_fn").l shouldBe empty
        auto.method.name("win_fn").l shouldBe empty
        auto.close()
      finally
        dir.delete()
        ext.delete()

    "treat a bare --define as gcc's -D: the name is 1 in an #if" in:
      val (dir, ext) = project()
      try
        val cpg = build(dir, _.withDefines(Set("CONFIG_FEATURE")))
        cpg.method.name("feature_fn").l should not be empty
        cpg.close()
      finally
        dir.delete()
        ext.delete()
end MacroCensusTests
