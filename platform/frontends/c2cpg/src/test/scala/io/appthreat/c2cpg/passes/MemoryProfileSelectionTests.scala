package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    MemoryApiPass,
    MemorySafetyFindingPass
}
import io.shiftleft.semanticcpg.language.*

import java.io.{ByteArrayOutputStream, PrintStream}

/** The declared library profiles meet the analysed tree: the headers a translation unit includes
  * decide which profile's entries govern its calls, a body the tree defines always says what its
  * own name means, an external config entry overrides a profile entry, and the declared entries
  * carry through the overlay to the allocation state and the mismatched-release rule. The fixtures
  * use declaration-only headers from the test resources standing in for the libraries' real ones,
  * so no body of a profile entry is ever in the analysed tree.
  */
class MemoryProfileSelectionTests extends DataFlowCodeToCpgSuite:

  /** The declaration-only stand-in headers, one directory per profile. */
  private val fixturesDir =
      better.files.File(
        java.nio.file.Paths.get(
          getClass.getClassLoader.getResource("profiles/glib/glib.h").toURI
        ).getParent.getParent
      )

  private def sourceOf(dir: String, file: String): String =
      (fixturesDir / dir / file).contentAsString

  /** Builds code with a profile's stand-in headers on the include path, exactly as a project build
    * would see the real ones.
    */
  private def cpgWith(
    dir: String,
    codeText: String,
    file: String
  ): io.shiftleft.codepropertygraph.Cpg =
      code(codeText, file).withConfig(
        Config(includeComments = true)
            .withIncludePaths(Set((fixturesDir / dir).pathAsString))
      )

  /** Runs the allocation-relevant part of the memory-safety overlay, as the memory-safety command
    * does (the API tags, the per-allocation state, the rules), and returns what the run printed.
    */
  private def runOverlay(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    externalConfig: Option[String] = None,
    profilesMode: String = MemoryApiPass.ProfilesAuto
  ): String =
      captureStdOut {
          new MemoryApiPass(cpg, externalConfig, profilesMode, reportProfiles = true).createAndApply()
          new AllocationStatePass(cpg).createAndApply()
          new MemorySafetyFindingPass(cpg, externalConfig).createAndApply()
      }._2

  /** Captures the console, so a run's profile line has to say what it did. Scala's `println` goes
    * through `scala.Console`, which caches its stream, so both it and `System.out` are redirected.
    */
  private def captureStdOut[A](body: => A): (A, String) =
    val original = System.out
    val captured = new ByteArrayOutputStream()
    System.setOut(new PrintStream(captured, true, "UTF-8"))
    try
      val result = scala.Console.withOut(System.out)(body)
      (result, captured.toString("UTF-8"))
    finally System.setOut(original)

  private def findingsIn(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    method: String
  ): Set[String] =
      cpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet

  "a translation unit that includes none of a profile's headers" should {

      val cpg = code(
        """
          |void *g_new0(unsigned long type_size, unsigned long n_structs);
          |
          |void *use_glib_without_including_it(unsigned long n)
          |{
          |    return g_new0(1, n);
          |}
          |""".stripMargin,
        "no_library_headers.c"
      )
      val printed = runOverlay(cpg)

      "get no entry of that profile" in {
          cpg.call.name("g_new0").tag.name.l should not contain "mem-alloc"
          cpg.call.name("g_new0").tag.name.l should not contain "memory-safety"
      }

      "be told that no profile was selected" in {
          printed should include("MemoryApiPass: memory-api profiles: none selected")
      }
  }

  "a body in the analysed tree" should {

      val cpg = cpgWith(
        "glib",
        """
          |#include <gmem.h>
          |
          |static unsigned char spare[32];
          |
          |/* The unit includes the allocator's header, but its own body for the same name says
          |   something else: a static block, not heap memory. What the tree defines governs. */
          |void *g_new0(unsigned long type_size, unsigned long n_structs)
          |{
          |    (void)type_size;
          |    (void)n_structs;
          |    return spare;
          |}
          |
          |void *own_body_wins(unsigned long n)
          |{
          |    return g_new0(1, n);
          |}
          |""".stripMargin,
        "own_body.c"
      )
      runOverlay(cpg)

      "win over the profile entry of the same name" in {
          cpg.call.name("g_new0").tag.name.l should not contain "mem-alloc"
          cpg.call.name("g_new0").tag.name.l should not contain "memory-safety"
      }
  }

  "a translation unit that includes a profile's headers" should {

      // One allocation idiom, one release idiom and one plain free() of the profile's allocation
      // per library, spelled as each library's own header declares it. `lenArg` is the argument
      // the profile's entry bounds the allocation by; `freeFamily` is None where the library's
      // release is a region role, which stays stored until a consumer reads it.
      val cases = List(
        (
          "glib",
          """#include <stdlib.h>
            |#include <gmem.h>
            |
            |void *block_with_glib(unsigned long n)
            |{
            |    return g_new0(1, n);
            |}
            |
            |void block_drop_with_glib(void *p)
            |{
            |    g_free(p);
            |}
            |
            |void wrong_release_with_glib(unsigned long n)
            |{
            |    void *p = g_new0(1, n);
            |    free(p);
            |}
            |""".stripMargin,
          "g_new0",
          "g_free",
          2,
          "heap",
          Some("heap")
        ),
        (
          "linux",
          """#include <stdlib.h>
            |#include <linux/slab.h>
            |#include <linux/gfp.h>
            |
            |void *block_with_linux(unsigned long n)
            |{
            |    return kmalloc(n, GFP_KERNEL);
            |}
            |
            |void block_drop_with_linux(void *p)
            |{
            |    kfree(p);
            |}
            |
            |void wrong_release_with_linux(unsigned long n)
            |{
            |    void *p = kmalloc(n, GFP_KERNEL);
            |    free(p);
            |}
            |""".stripMargin,
          "kmalloc",
          "kfree",
          1,
          "slab",
          Some("slab")
        ),
        (
          "postgresql",
          """#include <stdlib.h>
            |#include <postgres.h>
            |#include <utils/palloc.h>
            |
            |void *block_with_postgresql(void)
            |{
            |    return palloc(16);
            |}
            |
            |void block_drop_with_postgresql(void *p)
            |{
            |    pfree(p);
            |}
            |
            |void wrong_release_with_postgresql(void)
            |{
            |    void *p = palloc(16);
            |    free(p);
            |}
            |""".stripMargin,
          "palloc",
          "pfree",
          1,
          "pgmem",
          Some("pgmem")
        ),
        (
          "apr",
          """#include <stdlib.h>
            |#include <apr_pools.h>
            |
            |void *block_with_apr(apr_pool_t *pool)
            |{
            |    return apr_palloc(pool, 16);
            |}
            |
          |void pool_drop_with_apr(apr_pool_t *pool)
          |{
          |    apr_pool_destroy(pool);
          |}
          |
          |void wrong_release_with_apr(apr_pool_t *pool)
          |{
          |    void *p = apr_palloc(pool, 16);
          |    free(p);
          |}
          |""".stripMargin,
          "apr_palloc",
          "apr_pool_destroy",
          2,
          "aprpool",
          None
        ),
        (
          "nginx",
          """#include <stdlib.h>
            |#include <ngx_core.h>
            |#include <ngx_palloc.h>
            |
            |void *block_with_nginx(ngx_pool_t *pool)
            |{
            |    return ngx_palloc(pool, 16);
            |}
            |
            |void block_drop_with_nginx(void *p)
            |{
            |    ngx_free(p);
            |}
            |
            |void wrong_release_with_nginx(ngx_pool_t *pool)
            |{
            |    void *p = ngx_palloc(pool, 16);
            |    free(p);
            |}
            |""".stripMargin,
          "ngx_palloc",
          "ngx_free",
          2,
          "ngxpool",
          Some("heap")
        ),
        (
          "cpython",
          """#include <stdlib.h>
            |#include <pymem.h>
            |
            |void *block_with_cpython(void)
            |{
            |    return PyMem_Malloc(64);
            |}
            |
            |void block_drop_with_cpython(void *p)
            |{
            |    PyMem_Free(p);
            |}
            |
            |void wrong_release_with_cpython(void)
            |{
            |    void *p = PyMem_Malloc(64);
            |    free(p);
            |}
            |""".stripMargin,
          "PyMem_Malloc",
          "PyMem_Free",
          1,
          "pymem",
          Some("pymem")
        ),
        (
          "php",
          """#include <stdlib.h>
            |#include <zend_alloc.h>
            |
            |void *block_with_php(unsigned long n)
            |{
            |    return emalloc(n);
            |}
            |
            |void block_drop_with_php(void *p)
            |{
            |    efree(p);
            |}
            |
            |void wrong_release_with_php(unsigned long n)
            |{
            |    void *p = emalloc(n);
            |    free(p);
            |}
            |""".stripMargin,
          "emalloc",
          "efree",
          1,
          "zendmm",
          Some("zendmm")
        )
      )

      cases.foreach {
          case (profile, codeText, allocator, releaser, lenArg, allocFamily, freeFamily) =>
              s"govern the $profile idiom with the $profile profile's entries" in {
                  val cpg = cpgWith(profile, codeText, s"${profile}_selection.c")
                  val out = runOverlay(cpg)
                  // the profile entry governs: the header declares, no body exists in the tree.
                  // Both the idiom and the wrong-release twin allocate, so the value set matters.
                  cpg.call.name(allocator).tag.name("mem-alloc").value.l.toSet shouldBe Set(
                    allocFamily
                  )
                  freeFamily match
                    case Some(family) =>
                        cpg.call.name(releaser).tag.name("mem-free").value.l.toSet shouldBe Set(
                          family
                        )
                    case None =>
                        // a region role stays stored until a consumer reads it
                        cpg.call.name(releaser).tag.name("mem-free").l shouldBe empty
                  cpg.call.name(allocator).head.argument(lenArg).tag.name("mem-len").l should
                      not be empty
                  (out should include).regex(s"memory-api profiles: .*$profile \\(1 file\\)")
                  // glib hands its blocks to the plain heap's own free, so the wrong-release
                  // twin stays correct; every other library's family is its own
                  if allocFamily == "heap" then
                    findingsIn(cpg, s"wrong_release_with_$profile") should not contain
                        "MS-ALLOC-007"
                  else
                    findingsIn(cpg, s"wrong_release_with_$profile") should contain(
                      "MS-ALLOC-007"
                    )
              }
      }

      "let an external config entry override the profile entry" in {
          val external = """{"apis": [{"name": "g_new0", "alloc": "myheap", "count": 2}]}"""
          val cpg = cpgWith(
            "glib",
            sourceOf("glib", "glib_idiom.c"),
            "glib_external.c"
          )
          runOverlay(cpg, externalConfig = Some(external))
          cpg.call.name("g_new0").tag.name("mem-alloc").value.l.toSet shouldBe Set("myheap")
          // a name the config does not mention keeps the profile's entry
          cpg.call.name("g_free").tag.name("mem-free").value.l.toSet shouldBe Set("heap")
      }
  }

  "a translation unit that includes the device-managed allocator's header" should {

      val cpg = cpgWith(
        "linux",
        """#include <linux/device.h>
          |
          |struct device;
          |
          |void *keys_for_device(struct device *dev, unsigned long n, unsigned int flags)
          |{
          |    return devm_kzalloc(dev, n, flags);
          |}
          |
          |/* the probe's exits: the allocation belongs to the device on every one */
          |int probe_exit_with_devm(struct device *dev, unsigned long n, unsigned int flags)
          |{
          |    void *keys = devm_kzalloc(dev, n, flags);
          |    if (keys == NULL)
          |        return -1;
          |    if (n == 0)
          |        return -1;
          |    return 0;
          |}
          |""".stripMargin,
        "devm_selection.c"
      )
      val printed = runOverlay(cpg)

      "select the linux profile" in {
          (printed should include).regex(s"memory-api profiles: .*linux \\(1 file\\)")
      }

      "govern the devm idiom with the declared region role" in {
          cpg.call.name("devm_kzalloc").tag.name("mem-region").value.l.toSet shouldBe Set(
            "alloc:1"
          )
          cpg.call.name("devm_kzalloc").tag.name.l should contain("memory-safety")
      }

      "keep the device-owned allocation out of the probe's leak facts" in {
          findingsIn(cpg, "probe_exit_with_devm") shouldBe empty
          cpg.method.name("probe_exit_with_devm").ast
              .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
              .flatMap(_.tag.name("alloc-leak").value.l).l shouldBe empty
      }
  }

  "a translation unit that includes both the slab and the device headers" should {

      val cpg = cpgWith(
        "linux",
        """#include <linux/slab.h>
          |#include <linux/device.h>
          |
          |struct device;
          |
          |void *two_kinds(struct device *dev, unsigned long n, unsigned int flags)
          |{
          |    void *own = kmalloc(n, flags);
          |    void *keys = devm_kzalloc(dev, n, flags);
          |    if (own == NULL || keys == NULL)
          |    {
          |        free(own);
          |        return NULL;
          |    }
          |    return own;
          |}
          |""".stripMargin,
        "both_headers.c"
      )
      val printed = runOverlay(cpg)

      "select the linux profile exactly once" in {
          (printed should include).regex(s"memory-api profiles: .*linux \\(1 file\\)")
      }

      "govern both the slab and the devm idioms" in {
          cpg.call.name("kmalloc").tag.name("mem-alloc").value.l.toSet shouldBe Set("slab")
          cpg.call.name("devm_kzalloc").tag.name("mem-region").value.l.toSet shouldBe Set(
            "alloc:1"
          )
      }
  }

  "the kernel's allocator families" should {

      val cpg = cpgWith(
        "linux",
        """#include <linux/slab.h>
          |#include <linux/gfp.h>
          |#include <linux/vmalloc.h>
          |
          |void slab_freed_by_vfree(unsigned long n) { void *p = kmalloc(n, GFP_KERNEL); vfree(p); }
          |void vmalloc_freed_by_kfree(unsigned long n) { void *p = vmalloc(n); kfree(p); }
          |void kvmalloc_freed_by_kfree(unsigned long n) { void *p = kvmalloc(n, GFP_KERNEL); kfree(p); }
          |void slab_freed_by_kfree(unsigned long n) { void *p = kcalloc(n, 8, GFP_KERNEL); kfree(p); }
          |void vmalloc_freed_by_vfree(unsigned long n) { void *p = vmalloc(n); vfree(p); }
          |void slab_freed_by_kvfree(unsigned long n) { void *p = kmalloc_array(n, 8, GFP_KERNEL); kvfree(p); }
          |void vmalloc_freed_by_kvfree(unsigned long n) { void *p = vmalloc(n); kvfree(p); }
          |void kvmalloc_freed_by_kvfree(unsigned long n) { void *p = kvzalloc(n, GFP_KERNEL); kvfree(p); }
          |""".stripMargin,
        "kernel_families.c"
      )
      runOverlay(cpg)

      "report a release with the wrong allocator's free" in {
          findingsIn(cpg, "slab_freed_by_vfree") should contain("MS-ALLOC-007")
          findingsIn(cpg, "vmalloc_freed_by_kfree") should contain("MS-ALLOC-007")
          findingsIn(cpg, "kvmalloc_freed_by_kfree") should contain("MS-ALLOC-007")
      }

      "accept each allocator's own free, and kvfree for all three" in {
          List(
            "slab_freed_by_kfree",
            "vmalloc_freed_by_vfree",
            "slab_freed_by_kvfree",
            "vmalloc_freed_by_kvfree",
            "kvmalloc_freed_by_kvfree"
          ).foreach(m => findingsIn(cpg, m) should not contain "MS-ALLOC-007")
      }
  }

  "a unit that includes only a library's umbrella header" should {

      val cpg = cpgWith(
        "cpython",
        """#include <stdlib.h>
          |#include <Python.h>
          |
          |void wrong_release_through_umbrella(void)
          |{
          |    void *p = PyMem_Malloc(64);
          |    free(p);
          |}
          |""".stripMargin,
        "umbrella.c"
      )
      val printed = runOverlay(cpg)

      "select the library's profile" in {
          printed should include("MemoryApiPass: memory-api profiles: cpython (1 file)")
          findingsIn(cpg, "wrong_release_through_umbrella") should contain("MS-ALLOC-007")
      }
  }

  "the profiles mode" should {

      "turn selection off with none" in {
          val cpg = cpgWith(
            "glib",
            sourceOf("glib", "glib_idiom.c"),
            "glib_none.c"
          )
          val out = runOverlay(cpg, profilesMode = MemoryApiPass.ProfilesNone)
          cpg.call.name("g_new0").tag.name.l should not contain "mem-alloc"
          out should include("MemoryApiPass: memory-api profiles: none")
      }

      "select exactly the forced profiles, whatever the unit includes" in {
          val cpg = cpgWith(
            "glib",
            sourceOf("glib", "glib_idiom.c"),
            "glib_forced.c"
          )
          val out = runOverlay(cpg, profilesMode = "linux")
          // linux applies to the file's calls; glib's entries do not, although the unit includes
          // the library's headers
          cpg.call.name("g_new0").tag.name.l should not contain "mem-alloc"
          // the file calls none of linux's entries, so no file follows the forced profile
          out should include("MemoryApiPass: memory-api profiles: linux (0 files)")
      }

      "match forced profile names without regard to case" in {
          val cpg = cpgWith(
            "glib",
            sourceOf("glib", "glib_idiom.c"),
            "glib_forced_upper.c"
          )
          val out = runOverlay(cpg, profilesMode = "GLib")
          cpg.call.name("g_new0").tag.name.l should contain("mem-alloc")
          out should include("MemoryApiPass: memory-api profiles: glib (1 file)")
      }

      "count only the files whose calls a forced profile declares" in {
          val cpg = code(sourceOf("glib", "glib_idiom.c"), "glib_forced_count.c")
              .moreCode("int unrelated(int x) { return x + 1; }\n", "unrelated.c")
              .withConfig(
                Config(includeComments = true)
                    .withIncludePaths(Set((fixturesDir / "glib").pathAsString))
              )
          val out = runOverlay(cpg, profilesMode = "glib")
          out should include("MemoryApiPass: memory-api profiles: glib (1 file)")
      }

      "say that nothing was selected when no unit includes a listed header" in {
          val cpg = cpgWith(
            "none",
            sourceOf("none", "no_profile_headers.c"),
            "no_profile_headers.c"
          )
          val out = runOverlay(cpg)
          out should include("MemoryApiPass: memory-api profiles: none selected")
      }
  }
end MemoryProfileSelectionTests
