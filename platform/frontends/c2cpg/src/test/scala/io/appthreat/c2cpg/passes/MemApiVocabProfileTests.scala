package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{MemApiVocab, MemoryApiPass}
import io.shiftleft.semanticcpg.language.*

import java.io.{ByteArrayOutputStream, PrintStream}

/** The declared library profiles of the memory API vocabulary: how the profile section and its
  * roles decode, how a malformed role is rejected without losing the rest, how an external config
  * interacts with the profiles, and how the headers a translation unit includes select a profile.
  * The roles themselves stay data here; the tagging passes consult them only for a profile that was
  * selected for a translation unit.
  */
class MemApiVocabProfileTests extends CCodeToCpgSuite:

  /** Captures what a decoding failure prints, so a dropped entry has to SAY it was dropped. */
  private def withCapturedErr[A](body: => A): (A, String) =
    val original = System.err
    val captured = new ByteArrayOutputStream()
    System.setErr(new PrintStream(captured, true, "UTF-8"))
    try (body, captured.toString("UTF-8"))
    finally System.setErr(original)

  private val inhouseProfile =
      """{"profiles": [{"name": "inhouse", "headers": ["inhouse.h"], "entries": [
        |  {"name": "pool_get", "region": {"role": "allocate", "arg": 1}, "len": 2,
        |   "alloc": "inhouse", "source": "inhouse/pool.h:12"},
        |  {"name": "hand_off", "steal": 1, "source": "inhouse/pool.h:31"},
        |  {"name": "keep", "acquire": 1, "source": "inhouse/pool.h:40"},
        |  {"name": "give_back", "release": 1, "source": "inhouse/pool.h:48"},
        |  {"name": "wipe", "cleanup": true, "source": "inhouse/pool.h:55"},
        |  {"name": "ctx_alloc", "region": {"role": "allocate", "context": "WorkerContext"},
        |   "source": "inhouse/pool.h:60"},
        |  {"name": "ctx_reset", "region": {"role": "reset", "arg": 1}, "source": "inhouse/pool.h:64"},
        |  {"name": "ctx_new", "region": {"role": "create"}, "source": "inhouse/pool.h:68"},
        |  {"name": "ctx_new_out", "region": {"role": "create", "arg": 2}, "source": "inhouse/pool.h:69"},
        |  {"name": "ctx_drop", "region": {"role": "destroy", "arg": 1}, "source": "inhouse/pool.h:72"}
        |]}]}""".stripMargin

  private def inhouseEntries: Map[String, MemApiVocab.MemApiEntry] =
      MemApiVocab.profiles(Some(inhouseProfile))("inhouse").entries.map(e => e.name -> e).toMap

  // The fixtures include declaration-only headers from the test resources, standing in for the
  // library's real headers: no body of a profile entry is ever inside the analysed tree, so a
  // body can never outrank the declared entry.
  private val fixturesDir =
      better.files.File(
        java.nio.file.Paths.get(
          getClass.getClassLoader.getResource("profiles/glib/glib.h").toURI
        ).getParent.getParent
      )

  private val includeDirective = """(?m)^\s*#\s*include\s*[<"]([^">]+)[">]""".r

  private def sourceOf(dir: String, file: String): String =
      (fixturesDir / dir / file).contentAsString

  private def selectedBy(dir: String, file: String): Set[String] =
    val includes = includeDirective.findAllMatchIn(sourceOf(dir, file)).map(_.group(1)).toSet
    includes should not be empty
    MemApiVocab.selectProfiles(None, includes).keySet

  /** Builds the fixture through the C front end with its header on the include path and runs the
    * tagging pass, so the checks see exactly what a translation unit of the analysed tree would.
    */
  private def cpgOf(dir: String): io.shiftleft.codepropertygraph.Cpg =
    val file = s"${dir}_idiom.c"
    val cpg = code(sourceOf(dir, file), file).withConfig(
      io.appthreat.c2cpg.Config(includeComments = true)
          .withIncludePaths(Set((fixturesDir / dir).pathAsString))
    )
    new MemoryApiPass(cpg).createAndApply()
    cpg

  /** Checks one profile's fixture: every listed API reaches the graph as a call whose declaration
    * built only an empty-bodied stub (no body inference can outrank the declared entry), and the
    * entries the tagging pass consumes - the family and length roles, the region lifecycle roles,
    * the declared reference roles, and the steal and cleanup roles - govern their calls' tags.
    */
  private def checkProfile(dir: String, apis: Seq[String]): Unit =
    val cpg     = cpgOf(dir)
    val profile = MemApiVocab.profiles(None)(dir)
    apis.foreach { api =>
      val entry = profile.entries.find(_.name == api).getOrElse(
        fail(s"profile $dir declares no entry for $api")
      )
      withClue(s"$api: ") {
          // the call reaches the graph; the declaration builds only a stub method whose
          // body is empty, so no inference from a body can outrank the declared entry
          cpg.call.name(api).l should not be empty
          cpg.method.name(api).block.astChildren.l shouldBe empty
      }
      // the consumed families the entry declares land as tags, valued with the family
      val families = (entry.alloc.toList ++ entry.realloc.toList ++ entry.freeFamilies).toSet
      if families.nonEmpty then
        withClue(s"$api: ") {
            cpg.call.name(api).tag
                .filter(t =>
                    t.name == "mem-alloc" || t.name == "mem-free" || t.name == "mem-realloc"
                )
                .value.l.toSet shouldBe families
            cpg.call.name(api).tag.name.l should contain("memory-safety")
        }
      else if entry.len.isDefined || entry.count.isDefined || entry.dst.isDefined ||
        entry.src.isDefined || entry.nullableReturn
      then
        withClue(s"$api: ") {
            cpg.call.name(api).tag.name.l should contain("memory-safety")
        }
      else if entry.region.isDefined then
        withClue(s"$api: ") {
            // the region lifecycle role lands as its tag, valued with the encoded role, and
            // nothing else travels beside it: no family on a lifecycle entry
            val encoded = entry.region.get match
              case MemApiVocab.MemRegion("allocate", Some(i), _)    => s"alloc:$i"
              case MemApiVocab.MemRegion("allocate", None, Some(c)) => s"alloc:ctx:$c"
              case MemApiVocab.MemRegion("create", arg, _) =>
                  arg.map(i => s"create:$i").getOrElse("create")
              case MemApiVocab.MemRegion("destroy", Some(i), _) => s"destroy:$i"
              case MemApiVocab.MemRegion("reset", Some(i), _)   => s"reset:$i"
              case other                                        => other.role
            cpg.call.name(api).tag.name("mem-region").value.l.toSet shouldBe Set(encoded)
            cpg.call.name(api).tag.name.l should contain("memory-safety")
            cpg.call.name(api).tag.name.l should not contain "mem-alloc"
            cpg.call.name(api).tag.name.l should not contain "mem-free"
        }
      else if entry.release.isDefined || entry.acquire.isDefined then
        withClue(s"$api: ") {
            // the reference role lands as its tag, valued with the object's argument index
            entry.release.foreach(i =>
                cpg.call.name(api).tag.name("mem-release").value.l.toSet shouldBe Set(
                  i.toString
                )
            )
            entry.acquire.foreach(i =>
                cpg.call.name(api).tag.name("mem-acquire").value.l.toSet shouldBe Set(
                  i.toString
                )
            )
            cpg.call.name(api).tag.name.l should contain("memory-safety")
        }
      else if entry.steal.isDefined || entry.cleanup then
        withClue(s"$api: ") {
            // the steal and cleanup roles land as their tags, valued with the slot's index
            entry.steal.foreach(i =>
                cpg.call.name(api).tag.name("mem-steal").value.l.toSet shouldBe Set(i.toString)
            )
            if entry.cleanup then
              cpg.call.name(api).tag.name("mem-cleanup").value.l.toSet shouldBe Set("1")
            cpg.call.name(api).tag.name.l should contain("memory-safety")
        }
      else fail(s"profile $dir entry $api declares no role the tagging pass reads")
      end if
    }
    selectedBy(dir, s"${dir}_idiom.c") shouldBe Set(dir)
  end checkProfile

  "the profile section of the vocabulary" should {

      "decode every declared role of a profile entry" in {
          val entries = inhouseEntries
          entries("pool_get").region shouldBe Some(
            MemApiVocab.MemRegion("allocate", arg = Some(1))
          )
          entries("pool_get").alloc shouldBe Some("inhouse")
          entries("pool_get").len shouldBe Some(2)
          entries("hand_off").steal shouldBe Some(1)
          entries("keep").acquire shouldBe Some(1)
          entries("give_back").release shouldBe Some(1)
          entries("wipe").cleanup shouldBe true
          entries("ctx_alloc").region shouldBe Some(
            MemApiVocab.MemRegion("allocate", context = Some("WorkerContext"))
          )
          entries("ctx_reset").region shouldBe Some(
            MemApiVocab.MemRegion("reset", arg = Some(1))
          )
          entries("ctx_new").region shouldBe Some(MemApiVocab.MemRegion("create"))
          entries("ctx_new_out").region shouldBe Some(
            MemApiVocab.MemRegion("create", arg = Some(2))
          )
          entries("ctx_drop").region shouldBe Some(
            MemApiVocab.MemRegion("destroy", arg = Some(1))
          )
          entries("give_back").source shouldBe Some("inhouse/pool.h:48")
      }

      "decode the roles on a plain inventory entry too" in {
          // a config that declares an in-house role needs no profile to carry it
          val cfg   = """{"apis": [
            {"name": "pool_get", "region": {"role": "allocate", "arg": 2}, "len": 3,
             "alloc": "inhouse", "source": "inhouse/pool.h:12"}
          ]}"""
          val entry = MemApiVocab.inventory(Some(cfg))("pool_get")
          entry.region shouldBe Some(MemApiVocab.MemRegion("allocate", arg = Some(2)))
          entry.source shouldBe Some("inhouse/pool.h:12")
      }

      "drop an entry whose release field is not a parameter index, noting it" in {
          val cfg            = """{"profiles": [{"name": "inhouse", "headers": ["inhouse.h"], "entries": [
            {"name": "give_back", "release": "one", "source": "inhouse/pool.h:48"},
            {"name": "keep", "acquire": 1, "source": "inhouse/pool.h:40"}
          ]}]}"""
          val (profile, err) = withCapturedErr(MemApiVocab.profiles(Some(cfg))("inhouse"))
          profile.entries.map(_.name) shouldBe List("keep")
          err should include("warn")
          err should include("give_back")
          err should include("release")
      }

      "drop an entry whose region role is unknown or misshapen, noting each" in {
          val cfg            = """{"profiles": [{"name": "inhouse", "headers": ["inhouse.h"], "entries": [
            {"name": "odd_role", "region": {"role": "borrow", "arg": 1}, "source": "inhouse/pool.h:1"},
            {"name": "no_arg_reset", "region": {"role": "reset"}, "source": "inhouse/pool.h:2"},
            {"name": "both_ways", "region": {"role": "allocate", "arg": 1, "context": "Ctx"},
             "source": "inhouse/pool.h:3"},
            {"name": "bare_allocate", "region": {"role": "allocate"}, "source": "inhouse/pool.h:4"},
            {"name": "context_reset", "region": {"role": "reset", "context": "Ctx"},
             "source": "inhouse/pool.h:5"},
            {"name": "zero_index", "region": {"role": "create", "arg": 0}, "source": "inhouse/pool.h:6"},
            {"name": "string_index", "acquire": "1", "source": "inhouse/pool.h:7"},
            {"name": "fine", "region": {"role": "allocate", "arg": 2}, "source": "inhouse/pool.h:8"}
          ]}]}"""
          val (profile, err) = withCapturedErr(MemApiVocab.profiles(Some(cfg))("inhouse"))
          profile.entries.map(_.name) shouldBe List("fine")
          Seq(
            "odd_role",
            "no_arg_reset",
            "both_ways",
            "bare_allocate",
            "context_reset",
            "zero_index",
            "string_index"
          ).foreach { name =>
              err should include(name)
          }
      }

      "require a source citation for every profile entry" in {
          val cfg            = """{"profiles": [{"name": "inhouse", "headers": ["inhouse.h"], "entries": [
            {"name": "uncited", "release": 1},
            {"name": "blank_citation", "acquire": 1, "source": "  "},
            {"name": "cited", "release": 1, "source": "inhouse/pool.h:48"}
          ]}]}"""
          val (profile, err) = withCapturedErr(MemApiVocab.profiles(Some(cfg))("inhouse"))
          profile.entries.map(_.name) shouldBe List("cited")
          err should include("uncited")
          err should include("blank_citation")
      }

      "drop a profile without a name, headers or entries, noting it" in {
          val cfg             = """{"profiles": [
            {"headers": ["a.h"], "entries": [{"name": "x", "source": "a.h:1"}]},
            {"name": "headless", "entries": [{"name": "x", "source": "a.h:1"}]},
            {"name": "entryless", "headers": ["a.h"]}
          ]}"""
          val (profiles, err) = withCapturedErr(MemApiVocab.profiles(Some(cfg)))
          // every declared profile was unreadable, so only the built-in ones remain
          profiles.keySet shouldBe MemApiVocab.profiles(None).keySet
          err should include("headless")
          err should include("entryless")
      }
  }

  "external configs" should {

      "keep loading an entry list unchanged" in {
          val external = """{"version": 1, "apis": [
            {"name": "av_memcpy", "dst": 1, "src": 2, "len": 3},
            {"name": "memcpy", "dst": 4}
          ]}"""
          val inv      = MemApiVocab.inventory(Some(external))
          inv("av_memcpy").len shouldBe Some(3)
          inv("memcpy").dst shouldBe Some(4)
          inv("memcpy").len shouldBe None
      }

      "add no profiles when they declare none" in {
          val external = """{"version": 1, "apis": [
            {"name": "av_memcpy", "dst": 1, "src": 2, "len": 3}
          ]}"""
          MemApiVocab.profiles(Some(external)) shouldBe MemApiVocab.profiles(None)
      }

      "ignore an unreadable profiles array, noting it" in {
          val external        = """{"version": 1, "apis": [], "profiles": "yes"}"""
          val (profiles, err) = withCapturedErr(MemApiVocab.profiles(Some(external)))
          profiles shouldBe MemApiVocab.profiles(None)
          err should include("profiles")
      }

      "add an external profile by name" in {
          val external = """{"profiles": [{"name": "inhouse", "headers": ["vendor/pool.h"], "entries": [
            {"name": "pool_get", "region": {"role": "allocate", "arg": 1}, "source": "vendor/pool.h:12"}
          ]}]}"""
          val profiles = MemApiVocab.profiles(Some(external))
          profiles("inhouse").headers shouldBe List("vendor/pool.h")
          profiles("inhouse").entries.map(_.name) shouldBe List("pool_get")
      }

      "read a profiles-only config without a warning about its missing entry list" in {
          val external   = """{"profiles": [{"name": "inhouse", "headers": ["vendor/pool.h"], "entries": [
            {"name": "pool_get", "region": {"role": "allocate", "arg": 1}, "source": "vendor/pool.h:12"}
          ]}]}"""
          val (inv, err) = withCapturedErr(MemApiVocab.inventory(Some(external)))
          inv.keySet shouldBe MemApiVocab.inventory(None).keySet
          (err should not).include("apis")
      }

      "read the descriptor family by its earlier name" in {
          val external = """{"apis": [
            {"name": "my_socket", "alloc": "socket"},
            {"name": "my_close", "free": "socket"}
          ]}"""
          val inv      = MemApiVocab.inventory(Some(external))
          inv("my_socket").alloc shouldBe Some("fd")
          inv("my_close").freeFamilies shouldBe List("fd")
      }

      "read a release that accepts several families" in {
          val external = """{"apis": [{"name": "pool_or_heap_free", "free": ["heap", "pool"]}]}"""
          MemApiVocab.inventory(Some(external))("pool_or_heap_free").freeFamilies shouldBe List(
            "heap",
            "pool"
          )
      }

      "read the role that hands an argument's resource to the result" in {
          MemApiVocab.inventory(None)("fdopen").retains shouldBe Some(1)
      }
  }

  "the built-in library profiles" should {

      def entriesOf(profile: String): Map[String, MemApiVocab.MemApiEntry] =
          MemApiVocab.profiles(None)(profile).entries.map(e => e.name -> e).toMap

      "declare the seven library profiles by name with their selecting headers" in {
          val profiles = MemApiVocab.profiles(None)
          profiles.keySet shouldBe Set(
            "glib",
            "linux",
            "postgresql",
            "apr",
            "nginx",
            "cpython",
            "php"
          )
          profiles("glib").headers shouldBe List(
            "glib.h",
            "gmem.h",
            "glib-object.h",
            "gio/gio.h",
            "gtk/gtk.h"
          )
          profiles("linux").headers shouldBe List(
            "linux/slab.h",
            "linux/kref.h",
            "linux/gfp.h",
            "linux/vmalloc.h",
            "linux/device.h"
          )
          profiles("postgresql").headers shouldBe List(
            "postgres.h",
            "utils/palloc.h",
            "utils/memutils.h"
          )
          profiles("apr").headers shouldBe List("apr_pools.h", "httpd.h")
          profiles("nginx").headers shouldBe List("ngx_core.h", "ngx_palloc.h")
          profiles("cpython").headers shouldBe List("Python.h", "object.h", "pymem.h")
          profiles("php").headers shouldBe List(
            "php.h",
            "zend.h",
            "zend_API.h",
            "zend_alloc.h",
            "zend_string.h"
          )
      }

      "cite a source for every entry of every profile" in {
          MemApiVocab.profiles(None).values.foreach { profile =>
              withClue(s"profile ${profile.name}: ") {
                  profile.entries should not be empty
                  profile.headers should not be empty
                  profile.entries.foreach { entry =>
                      withClue(s"entry ${entry.name}: ") {
                          entry.source.exists(_.trim.nonEmpty) shouldBe true
                      }
                  }
              }
          }
      }

      "let an external profile replace a built-in one wholesale" in {
          val external = """{"profiles": [{"name": "glib", "headers": ["glib.h"], "entries": [
            {"name": "g_malloc", "alloc": "heap", "source": "glib/gmem.h"}
          ]}]}"""
          val profiles = MemApiVocab.profiles(Some(external))
          profiles("glib").headers shouldBe List("glib.h")
          profiles("glib").entries.map(_.name) shouldBe List("g_malloc")
      }

      "declare the glib allocators on the heap family, with the steal role" in {
          val glib = entriesOf("glib")
          glib.keySet shouldBe Set(
            "g_new0",
            "g_free",
            "g_steal_pointer",
            "g_autoptr_cleanup_generic_gfree"
          )
          glib("g_new0").alloc shouldBe Some("heap")
          glib("g_new0").count shouldBe Some(2)
          glib("g_free").free shouldBe Some("heap")
          // g_free is free() on every platform glib supports; the citation says where that is stated
          (glib("g_free").source.exists(s =>
              s.contains("2.46") && s.contains("system malloc")
          )) shouldBe
              true
          glib("g_steal_pointer").steal shouldBe Some(1)
          glib("g_autoptr_cleanup_generic_gfree").cleanup shouldBe true
      }

      "declare the kernel's slab, vmalloc and kvmalloc families with their frees" in {
          val linux = entriesOf("linux")
          linux.keySet shouldBe Set(
            "kmalloc",
            "kzalloc",
            "kcalloc",
            "kmalloc_array",
            "kvmalloc",
            "kvzalloc",
            "vmalloc",
            "kfree",
            "vfree",
            "kvfree",
            "devm_kzalloc",
            "devm_kcalloc",
            "kref_put"
          )
          linux("kmalloc").alloc shouldBe Some("slab")
          linux("kmalloc").len shouldBe Some(1)
          linux("kzalloc").alloc shouldBe Some("slab")
          linux("kcalloc").alloc shouldBe Some("slab")
          linux("kcalloc").count shouldBe Some(1)
          linux("kcalloc").len shouldBe Some(2)
          linux("vmalloc").alloc shouldBe Some("vmalloc")
          linux("vmalloc").len shouldBe Some(1)
          linux("kvmalloc").alloc shouldBe Some("kvmalloc")
          linux("kfree").freeFamilies shouldBe List("slab")
          linux("vfree").freeFamilies shouldBe List("vmalloc")
          // kvfree accepts the memory of all three allocators, which its family list says; the
          // citation names the slab header that declares it and the slub kerneldoc that states it
          linux("kvfree").freeFamilies shouldBe List("slab", "vmalloc", "kvmalloc")
          linux("kvfree").source.exists(s =>
              s.contains("linux/slab.h") && s.contains("vmalloc(), kmalloc() or kvmalloc()")
          ) shouldBe true
          linux("devm_kzalloc").region shouldBe Some(
            MemApiVocab.MemRegion("allocate", arg = Some(1))
          )
          linux("devm_kzalloc").len shouldBe Some(2)
          // the device-managed array allocation counts its elements and belongs to the device
          linux("devm_kcalloc").count shouldBe Some(2)
          linux("devm_kcalloc").len shouldBe Some(3)
          linux("devm_kcalloc").region shouldBe Some(
            MemApiVocab.MemRegion("allocate", arg = Some(1))
          )
          linux("kref_put").release shouldBe Some(1)
          // the release callback kref_put calls at zero is its second argument
          linux("kref_put").source.exists(_.contains("argument 2")) shouldBe true
      }

      "declare the postgresql context family and region roles" in {
          val pg = entriesOf("postgresql")
          pg.keySet shouldBe Set(
            "palloc",
            "palloc0",
            "pfree",
            "MemoryContextReset",
            "MemoryContextDelete",
            "AllocSetContextCreate"
          )
          val currentContext =
              MemApiVocab.MemRegion("allocate", context = Some("CurrentMemoryContext"))
          pg("palloc").region shouldBe Some(currentContext)
          pg("palloc").alloc shouldBe Some("pgmem")
          pg("palloc").len shouldBe Some(1)
          pg("palloc0").region shouldBe Some(currentContext)
          pg("pfree").free shouldBe Some("pgmem")
          pg("MemoryContextReset").region shouldBe Some(
            MemApiVocab.MemRegion("reset", arg = Some(1))
          )
          pg("MemoryContextDelete").region shouldBe Some(
            MemApiVocab.MemRegion("destroy", arg = Some(1))
          )
          pg("AllocSetContextCreate").region shouldBe Some(MemApiVocab.MemRegion("create"))
      }

      "declare the apr pool family and lifecycle roles" in {
          val apr = entriesOf("apr")
          apr.keySet shouldBe Set(
            "apr_palloc",
            "apr_pool_create",
            "apr_pool_clear",
            "apr_pool_destroy"
          )
          apr("apr_palloc").region shouldBe Some(
            MemApiVocab.MemRegion("allocate", arg = Some(1))
          )
          apr("apr_palloc").alloc shouldBe Some("aprpool")
          apr("apr_palloc").len shouldBe Some(2)
          // the new pool is handed out through the first argument, an out-pointer
          apr("apr_pool_create").region shouldBe Some(
            MemApiVocab.MemRegion("create", arg = Some(1))
          )
          apr("apr_pool_clear").region shouldBe Some(
            MemApiVocab.MemRegion("reset", arg = Some(1))
          )
          apr("apr_pool_destroy").region shouldBe Some(
            MemApiVocab.MemRegion("destroy", arg = Some(1))
          )
      }

      "declare the nginx heap wrappers and the pool family" in {
          val nginx = entriesOf("nginx")
          nginx.keySet shouldBe Set(
            "ngx_alloc",
            "ngx_free",
            "ngx_palloc",
            "ngx_create_pool",
            "ngx_destroy_pool"
          )
          nginx("ngx_alloc").alloc shouldBe Some("heap")
          nginx("ngx_free").free shouldBe Some("heap")
          nginx("ngx_palloc").region shouldBe Some(
            MemApiVocab.MemRegion("allocate", arg = Some(1))
          )
          nginx("ngx_palloc").alloc shouldBe Some("ngxpool")
          nginx("ngx_create_pool").region shouldBe Some(MemApiVocab.MemRegion("create"))
          nginx("ngx_destroy_pool").region shouldBe Some(
            MemApiVocab.MemRegion("destroy", arg = Some(1))
          )
      }

      "declare the pymem family and the reference count roles" in {
          val cpython = entriesOf("cpython")
          cpython.keySet shouldBe Set(
            "PyMem_Malloc",
            "PyMem_Free",
            "Py_DECREF",
            "Py_INCREF"
          )
          cpython("PyMem_Malloc").alloc shouldBe Some("pymem")
          cpython("PyMem_Malloc").len shouldBe Some(1)
          cpython("PyMem_Free").free shouldBe Some("pymem")
          cpython("Py_DECREF").release shouldBe Some(1)
          cpython("Py_INCREF").acquire shouldBe Some(1)
      }

      "declare the php request allocator family and the string release role" in {
          val php = entriesOf("php")
          php.keySet shouldBe Set("emalloc", "efree", "zend_string_release")
          // the request heap belongs to the library's own allocator: a plain free of it stays a
          // mismatch, so it is a family of its own like the interpreter's
          php("emalloc").alloc shouldBe Some("zendmm")
          php("efree").free shouldBe Some("zendmm")
          php("zend_string_release").release shouldBe Some(1)
      }
  }

  "profile selection" should {

      val vendorProfile =
          """{"profiles": [{"name": "inhouse", "headers": ["vendor/pool.h", "vendor/misc.h"],
            | "entries": [{"name": "pool_get", "region": {"role": "allocate", "arg": 1},
            |              "source": "vendor/pool.h:12"}]}]}""".stripMargin

      "select a profile when one of its headers is included, matched by basename" in {
          val byBasename = MemApiVocab.selectProfiles(Some(vendorProfile), Set("pool.h"))
          byBasename.keySet shouldBe Set("inhouse")
          val byPath =
              MemApiVocab.selectProfiles(Some(vendorProfile), Set("vendor/misc.h", "stdio.h"))
          byPath.keySet shouldBe Set("inhouse")
      }

      "select nothing for headers no listed profile declares" in {
          val selected = MemApiVocab.selectProfiles(Some(vendorProfile), Set("stdio.h", "stdlib.h"))
          selected.keySet shouldBe Set.empty
          MemApiVocab.selectProfiles(Some(vendorProfile), Set.empty[String]).keySet shouldBe Set.empty
      }
  }

  "a translation unit that includes a profile's headers" should {

      "select the glib profile for a unit including glib's headers" in {
          checkProfile(
            "glib",
            Seq("g_new0", "g_free", "g_steal_pointer", "g_autoptr_cleanup_generic_gfree")
          )
      }

      "select the linux profile for a unit including the kernel headers" in {
          checkProfile(
            "linux",
            Seq(
              "kmalloc",
              "kzalloc",
              "vmalloc",
              "kfree",
              "kvfree",
              "devm_kzalloc",
              "devm_kcalloc",
              "kref_put"
            )
          )
      }

      "select the postgresql profile for a unit including the server headers" in {
          checkProfile(
            "postgresql",
            Seq(
              "palloc",
              "palloc0",
              "pfree",
              "AllocSetContextCreate",
              "MemoryContextReset",
              "MemoryContextDelete"
            )
          )
      }

      "select the apr profile for a unit including the pool header" in {
          checkProfile(
            "apr",
            Seq("apr_palloc", "apr_pool_create", "apr_pool_clear", "apr_pool_destroy")
          )
      }

      "select the nginx profile for a unit including the core headers" in {
          checkProfile(
            "nginx",
            Seq("ngx_alloc", "ngx_free", "ngx_palloc", "ngx_create_pool", "ngx_destroy_pool")
          )
      }

      "select the cpython profile for a unit including the interpreter headers" in {
          checkProfile("cpython", Seq("PyMem_Malloc", "PyMem_Free", "Py_DECREF", "Py_INCREF"))
      }

      "select the php profile for a unit including the engine headers" in {
          checkProfile("php", Seq("emalloc", "efree", "zend_string_release"))
      }

      "select no profile for a unit that includes none of the listed headers" in {
          selectedBy("none", "no_profile_headers.c") shouldBe Set.empty
      }
  }
end MemApiVocabProfileTests
