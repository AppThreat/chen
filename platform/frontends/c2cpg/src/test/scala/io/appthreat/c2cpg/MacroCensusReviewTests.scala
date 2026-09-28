package io.appthreat.c2cpg

import better.files.File
import _root_.io.appthreat.c2cpg.parser.MacroCensus
import _root_.io.appthreat.c2cpg.parser.MacroCensus.Tier
import _root_.io.appthreat.c2cpg.passes.AstCreationPass
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/** Review of the macro census: the lexer, the baseline-visible line count, the tiering and the
  * inputs it must honour.
  */
class MacroCensusReviewTests extends AnyWordSpec with Matchers:

  private def lines(n: Int, tag: String): String =
      (1 to n).map(i => s"int ${tag}_$i;").mkString("\n")

  private def census(files: (String, String)*)(ext: (String, String)*)
    : Map[String, MacroCensus.Entry] =
    val dir = File.newTemporaryDirectory("census-review")
    val out = File.newTemporaryDirectory("census-review-ext")
    try
      files.foreach { (p, t) => (dir / p).createIfNotExists(createParents = true).write(t) }
      ext.foreach { (p, t) => (out / p).createIfNotExists(createParents = true).write(t) }
      MacroCensus.analyseTree(dir.path, List(out.path), Set.empty).entries.map(e => e.name -> e).toMap
    finally
      dir.delete()
      out.delete()

  "the lexer" should:
    "not open a comment inside a string literal" in:
      val e = census("a.c" -> s"""#ifdef HAVE_GLOB
           |const char *p = "/tmp/*";
           |#else /* !HAVE_GLOB */
           |${lines(5, "g")}
           |#endif
           |""".stripMargin)()
      e("HAVE_GLOB").gainLines shouldBe -4
      e("HAVE_GLOB").tier shouldBe Tier.Skip

    "read C23 #elifdef as a branch of its own" in:
      val e = census("a.c" -> s"""#ifdef CONFIG_A
           |${lines(3, "a")}
           |#elifdef CONFIG_B
           |${lines(3, "b")}
           |#endif
           |""".stripMargin)()
      e("CONFIG_A").mixedUses shouldBe 1
      e("CONFIG_B").mixedUses shouldBe 1

    "continue a directive through a block comment that spans lines" in:
      val e = census("a.c" -> s"""#if CONFIG_FOO /* a comment
           | that runs on */ && CONFIG_BAR
           |${lines(4, "f")}
           |#endif
           |""".stripMargin)()
      e("CONFIG_FOO").mixedUses shouldBe 1
      e.keySet should contain("CONFIG_BAR")

    "read a comment as a space, a BOM and CR-only line ends" in:
      val e = census(
        "a.c" -> s"﻿#if/**/CONFIG_X\r${lines(3, "x").replace('\n', '\r')}\r#endif\r"
      )()
      e("CONFIG_X").gainLines shouldBe 3

    "not take names from __has_include arguments or number suffixes" in:
      val e = census("a.c" -> s"""#if __has_include(<port/port_config.h>) && 0x10UL > CONFIG_N
           |${lines(2, "p")}
           |#endif
           |""".stripMargin)()
      e.keySet should contain("CONFIG_N")
      e.keySet should not contain "port"
      e.keySet should not contain "h"
      e.keySet should not contain "x10UL"

  "the line count" should:
    "not credit an outer switch with the lines of an inner block the baseline hides" in:
      val e = census("a.c" -> s"""#if CONFIG_FAST
           |#ifdef _WIN32
           |${lines(20, "w")}
           |#endif
           |int fast;
           |#else
           |${lines(5, "s")}
           |#endif
           |""".stripMargin)()
      e("CONFIG_FAST").gainLines shouldBe -4
      e("CONFIG_FAST").tier shouldBe Tier.Skip

    "give nothing to a switch inside a block the baseline hides" in:
      val e = census("a.c" -> s"""#if 0
           |#ifdef CONFIG_DEAD
           |${lines(20, "d")}
           |#endif
           |#endif
           |""".stripMargin)()
      e("CONFIG_DEAD").gainLines shouldBe 0
      e("CONFIG_DEAD").tier shouldBe Tier.Skip

    "count nested build switches, which the auto tier defines together" in:
      val e = census("a.c" -> s"""#if CONFIG_NETWORK
           |#if CONFIG_TLS
           |${lines(10, "t")}
           |#endif
           |#endif
           |""".stripMargin)()
      e("CONFIG_NETWORK").gainLines shouldBe 10
      e("CONFIG_TLS").gainLines shouldBe 10

    "count the code inside a header's include guard" in:
      val e = census("cfg.h" -> s"""#ifndef CFG_H
           |#define CFG_H
           |#if CONFIG_GUARDED
           |${lines(4, "g")}
           |#endif
           |#endif
           |""".stripMargin)()
      e("CONFIG_GUARDED").gainLines shouldBe 4
      e("CONFIG_GUARDED").tier shouldBe Tier.Auto

    "not count stub lines as code a switch hides" in:
      val e = census(
        "config.h.in" -> "#cmakedefine01 HAVE_SNAPPY\n",
        "port.h" -> """#if HAVE_SNAPPY
           |  size_t outlen = snappy_max(length);
           |  output->resize(outlen);
           |  snappy_raw_compress(input, length, &(*output)[0], &outlen);
           |  return true;
           |#else
           |  // Silence compiler warnings about unused arguments.
           |  (void)input;
           |  (void)length;
           |  (void)output;
           |  return false;
           |#endif
           |""".stripMargin
      )()
      e("HAVE_SNAPPY").gainLines shouldBe 3
      e("HAVE_SNAPPY").tier shouldBe Tier.Auto

  "the tiering" should:
    "skip a template name that carries a value" in:
      val e = census(
        "config.h.in" -> "#cmakedefine FOO_DATADIR \"@FOO_DATADIR@\"\n#cmakedefine HAVE_SWITCH\n",
        "a.c" -> s"""#ifdef FOO_DATADIR
           |${lines(3, "d")}
           |#endif
           |#ifdef HAVE_SWITCH
           |${lines(3, "s")}
           |#endif
           |""".stripMargin
      )()
      e("FOO_DATADIR").tier shouldBe Tier.Skip
      e("HAVE_SWITCH").tier shouldBe Tier.Auto

    "suggest, not auto-define, a name the tree defines under another condition" in:
      val e = census("udp.c" -> s"""#if HAVE_W32THREADS
           |#define CONFIG_PTHREAD_CANCEL 1
           |#endif
           |#if CONFIG_PTHREAD_CANCEL
           |${lines(10, "c")}
           |#endif
           |""".stripMargin)()
      e("CONFIG_PTHREAD_CANCEL").tier shouldBe Tier.Suggest

    "see through an include guard and a default" in:
      val e = census(
        "cfg.h" -> """#ifndef CFG_H
           |#define CFG_H
           |#define CONFIG_INTERNAL 1
           |#ifndef CONFIG_DEFAULTED
           |#define CONFIG_DEFAULTED 0
           |#endif
           |#endif
           |""".stripMargin,
        "a.c" -> s"""#if CONFIG_INTERNAL
           |${lines(3, "i")}
           |#endif
           |#if CONFIG_DEFAULTED
           |${lines(3, "d")}
           |#endif
           |""".stripMargin
      )()
      e.keySet should not contain "CONFIG_INTERNAL"
      e.keySet should not contain "CONFIG_DEFAULTED"

    "count only headers the tree includes as defining a name" in:
      val e = census("a.c" -> s"""#include "used.h"
           |#ifdef HAVE_MMAP
           |${lines(3, "m")}
           |#endif
           |#ifdef HAVE_USED
           |${lines(3, "u")}
           |#endif
           |""".stripMargin)(
        "unused.h" -> "#define HAVE_MMAP 1\n",
        "used.h"   -> "#include \"deeper.h\"\n",
        "deeper.h" -> "#define HAVE_USED 1\n"
      )
      e("HAVE_MMAP").tier shouldBe Tier.Suggest
      e.keySet should not contain "HAVE_USED"

    "match platform words as whole tokens" in:
      val e = census("a.c" -> s"""#ifdef HAVE_ALARM
           |${lines(3, "a")}
           |#endif
           |#if CONFIG_THUMB
           |${lines(3, "t")}
           |#endif
           |#ifdef EXPERIMENTAL
           |${lines(3, "e")}
           |#endif
           |#ifdef ENOMEDIUM
           |${lines(3, "n")}
           |#endif
           |""".stripMargin)()
      e("HAVE_ALARM").tier shouldBe Tier.Suggest
      e("CONFIG_THUMB").tier shouldBe Tier.Skip
      e("EXPERIMENTAL").tier shouldBe Tier.Suggest
      e("ENOMEDIUM").reason shouldBe "errno constant"

  "the inputs" should:
    "ignore a census header written inside the tree" in:
      val e = census(
        "census.h" -> s"${MacroCensus.GeneratedMarker} Review before use.\n#define CONFIG_FEATURE 1\n",
        "a.c" -> s"""#if CONFIG_FEATURE
           |${lines(3, "f")}
           |#endif
           |""".stripMargin
      )()
      e("CONFIG_FEATURE").tier shouldBe Tier.Auto

    "leave names in --macro-files and --include-files to the user" in:
      val dir = File.newTemporaryDirectory("census-user")
      val mf  = File.newTemporaryFile("census", ".h")
      try
        (dir / "a.c").write(s"""#if CONFIG_FEATURE
             |${lines(3, "f")}
             |#endif
             |#if CONFIG_OTHER
             |${lines(3, "o")}
             |#endif
             |""".stripMargin)
        mf.write("/* #undef CONFIG_FEATURE */\n")
        val report = MacroCensus.run(
          Config().withInputPath(dir.pathAsString).withMacroFiles(Set(mf.pathAsString))
        )
        report.entries.map(_.name) should not contain "CONFIG_FEATURE"
        report.auto.map(_.name) should contain("CONFIG_OTHER")
      finally
        dir.delete()
        mf.delete()

    "survive an unreadable directory" in:
      // POSIX permissions make the directory unreadable; Windows has no such view (ACLs), and the
      // walk's failure handling is the same code there
      assume(
        java.nio.file.FileSystems.getDefault.supportedFileAttributeViews.contains("posix"),
        "needs POSIX file permissions"
      )
      val dir    = File.newTemporaryDirectory("census-perm")
      val locked = dir / "locked"
      try
        locked.createDirectories()
        (locked / "x.c").write("#if CONFIG_HIDDEN\nint h;\n#endif\n")
        (dir / "a.c").write(s"#if CONFIG_FEATURE\n${lines(3, "f")}\n#endif\n")
        Files.setPosixFilePermissions(locked.path, PosixFilePermissions.fromString("---------"))
        val report = MacroCensus.run(Config().withInputPath(dir.pathAsString))
        report.auto.map(_.name) should contain("CONFIG_FEATURE")
      finally
        Files.setPosixFilePermissions(locked.path, PosixFilePermissions.fromString("rwx------"))
        dir.delete()

    "write the reports into a directory that does not exist yet" in:
      val dir = File.newTemporaryDirectory("census-out")
      try
        (dir / "src" / "a.c").createIfNotExists(createParents = true)
            .write(s"#if CONFIG_FEATURE\n${lines(3, "f")}\n#endif\n")
        val base = (dir / "reports" / "nested" / "census.h").pathAsString
        val cfg  = Config().withInputPath((dir / "src").pathAsString).withMacroCensusReport(base)
        C2Cpg.writeReport(cfg, MacroCensus.run(cfg))
        (dir / "reports" / "nested" / "census.json").exists shouldBe true
        (dir / "reports" / "nested" / "census.h").contentAsString should include(
          "#define CONFIG_FEATURE 1"
        )
      finally dir.delete()

  "the AST cache fingerprint" should:
    "change when a macro file's content changes" in:
      val mf = File.newTemporaryFile("census-fp", ".h")
      try
        mf.write("#define A 1\n")
        val cfg    = Config().withMacroFiles(Set(mf.pathAsString))
        val before = AstCreationPass.cacheFingerprint(cfg)
        mf.write("#define A 2\n")
        AstCreationPass.cacheFingerprint(cfg) should not be before
      finally mf.delete()
end MacroCensusReviewTests
