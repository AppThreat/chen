package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{MemApiVocab, MemoryApiPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

/** MemoryApiPass: tags only - roles come from the inventory, arguments get the tags, every
  * fine-grained tag travels with the `memory-safety` umbrella. The wrapper inference concludes
  * roles from method bodies - never names - and is conservative: anything but a clean allocation
  * flow or a pure free wrapper stays untagged.
  */
class MemoryApiPassTests extends CCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <string.h>
    |#include <stdlib.h>
    |#include <unistd.h>
    |
    |int process(int fd, char *src, int n) {
    |    char buf[64];
    |    char *heap = malloc(128);
    |    char *grid = calloc(n, sizeof(char));
    |    memcpy(buf, src, n);
    |    snprintf(buf, sizeof(buf), "%s", src);
    |    read(fd, buf, n);
    |    heap = realloc(heap, 256);
    |    free(heap);
    |    free(grid);
    |    return readlink(src, buf, n);
    |}
    |""".stripMargin,
    "probe.c"
  )

  // Apply the pass to the fixture the way atom's enhancement pipeline does.
  new MemoryApiPass(cpg).createAndApply()

  private def tagValues(node: Any): Set[String] =
      node match
        case c: Call => c.tag.name.l.toSet
        case n =>
            n.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].tag.name.l.toSet

  private def call(name: String): Call = cpg.call.name(name).head

  // The declared region vocabulary, the way a project's in-house config names its pools and
  // contexts: argument-indexed pools, a context-less allocator reading a global, and the
  // lifecycle roles.
  private val regionConfig =
      """{"version": 1, "apis": [
        |  {"name": "palloc", "len": 1, "alloc": "pgmem",
        |   "region": {"role": "allocate", "context": "CurrentMemoryContext"}},
        |  {"name": "pfree", "free": "pgmem"},
        |  {"name": "apr_palloc", "len": 2, "alloc": "aprpool",
        |   "region": {"role": "allocate", "arg": 1}},
        |  {"name": "apr_pool_create", "region": {"role": "create", "arg": 1}},
        |  {"name": "apr_pool_clear", "region": {"role": "reset", "arg": 1}},
        |  {"name": "apr_pool_destroy", "region": {"role": "destroy", "arg": 1}}
        |]}""".stripMargin

  private val regionCpg: Cpg = code(
    """
    |#include <stdlib.h>
    |
    |void *palloc(unsigned long size);
    |void pfree(void *p);
    |extern void *CurrentMemoryContext;
    |typedef struct apr_pool_t apr_pool_t;
    |void *apr_palloc(apr_pool_t *pool, unsigned long size);
    |void apr_pool_create(apr_pool_t **pool, apr_pool_t *parent);
    |void apr_pool_clear(apr_pool_t *pool);
    |void apr_pool_destroy(apr_pool_t *pool);
    |
    |void *take_from_pool(apr_pool_t *pool)
    |{
    |    return apr_palloc(pool, 16);
    |}
    |
    |void make_pool(apr_pool_t **out, apr_pool_t *parent)
    |{
    |    apr_pool_create(out, parent);
    |}
    |
    |void recycle_pool(apr_pool_t *pool)
    |{
    |    apr_pool_clear(pool);
    |}
    |
    |void drop_pool(apr_pool_t *pool)
    |{
    |    apr_pool_destroy(pool);
    |}
    |
    |void *take_from_context(void)
    |{
    |    return palloc(16);
    |}
    |
    |void give_back(void *p)
    |{
    |    pfree(p);
    |}
    |""".stripMargin,
    "regions.c"
  )
  new MemoryApiPass(regionCpg, Some(regionConfig)).createAndApply()

  private def regionCall(name: String): Call = regionCpg.call.name(name).head

  // The declared reference roles, the way a project's in-house config names its reference-counted
  // pair, beside a release the analysed tree's own body concludes.
  private val refConfig =
      """{"version": 1, "apis": [
        |  {"name": "obj_keep", "acquire": 1},
        |  {"name": "obj_drop", "release": 1}
        |]}""".stripMargin

  private val refConfigCpg: Cpg = code(
    """
    |void obj_keep(void *o);
    |void obj_drop(void *o);
    |
    |void keep_once(void *o)
    |{
    |    obj_keep(o);
    |}
    |
    |void drop_once(void *o)
    |{
    |    obj_drop(o);
    |}
    |""".stripMargin,
    "ref_roles.c"
  )
  new MemoryApiPass(refConfigCpg, Some(refConfig)).createAndApply()

  private val inferredRefCpg: Cpg = code(
    """
    |#include <stdlib.h>
    |
    |typedef struct gref { int refs; } gref_t;
    |void gref_unref(gref_t *o)
    |{
    |    if (--o->refs == 0) {
    |        free(o);
    |    }
    |}
    |void gref_ref(gref_t *o)
    |{
    |    o->refs++;
    |}
    |void balanced_ok(gref_t *o)
    |{
    |    gref_ref(o);
    |    gref_unref(o);
    |}
    |""".stripMargin,
    "ref_inferred.c"
  )
  new MemoryApiPass(inferredRefCpg).createAndApply()

  private def refCall(name: String): Call = refConfigCpg.call.name(name).head

  "MemoryApiPass" should {

      "tag the roles of memcpy's arguments by index from the inventory" in {
          val memcpy = call("memcpy")
          memcpy.argument(1).tag.name.l should contain("mem-dst")
          memcpy.argument(2).tag.name.l should contain("mem-src")
          memcpy.argument(3).tag.name.l should contain("mem-len")
          // value = the API name, so a consumer can tell which API put the tag there
          memcpy.argument(3).tag.name("mem-len").value.l shouldBe List("memcpy")
      }

      "tag BOTH factors of a count-by-size allocator as mem-len" in {
          // calloc(nmemb, size): the size that can overflow is the product, so the element
          // count carries mem-len too and ValueOrigin can attribute an origin to it
          val calloc = call("calloc")
          calloc.argument(1).tag.name.l should contain("mem-len")
          calloc.argument(2).tag.name.l should contain("mem-len")
          calloc.tag.name("mem-alloc").value.l shouldBe List("heap")
      }

      "let snprintf's different arity come free from the resource" in {
          // snprintf(dst, size, fmt, ...) - the destination is argument 1, the length argument 2,
          // not memcpy's argument 3. No hard-coded indices anywhere in the consumer.
          val snprintf = call("snprintf")
          snprintf.argument(1).tag.name.l should contain("mem-dst")
          snprintf.argument(2).tag.name.l should contain("mem-len")
          snprintf.argument(2).tag.name("mem-len").value.l shouldBe List("snprintf")
      }

      "tag allocations and releases with their family" in {
          val malloc = call("malloc")
          malloc.tag.name.l should contain("mem-alloc")
          malloc.tag.name("mem-alloc").value.l shouldBe List("heap")
          malloc.argument(1).tag.name.l should contain("mem-len")
          call("free").tag.name("mem-free").value.l shouldBe List("heap")
      }

      "make a realloc the third family, not alloc AND free" in {
          val realloc = call("realloc")
          realloc.tag.name("mem-realloc").value.l shouldBe List("heap")
          // the two release/allocate sets are read as disjoint downstream: a call carrying
          // both would be a double-free and a fresh allocation at once
          realloc.tag.name.l should not contain "mem-alloc"
          realloc.tag.name.l should not contain "mem-free"
          // the byte size still bounds the new allocation
          realloc.argument(2).tag.name.l should contain("mem-len")
      }

      "tag the call and the filled buffer for untrusted readers" in {
          val read = call("read")
          read.tag.name.l should contain("untrusted-read")
          // read(fd, buf, count): the buffer is argument 2 - again different from memcpy
          read.argument(2).tag.name.l should contain("untrusted-read")
          read.argument(3).tag.name.l should contain("mem-len")
          val readlink = call("readlink")
          readlink.argument(2).tag.name.l should contain("untrusted-read")
      }

      "emit the memory-safety umbrella alongside every fine-grained tag" in {
          cpg.tag.name("mem-dst").l should not be empty
          cpg.tag.name("mem-src").l should not be empty
          cpg.tag.name("mem-len").l should not be empty
          cpg.tag.name("mem-alloc").l should not be empty
          cpg.tag.name("mem-free").l should not be empty
          cpg.tag.name("mem-realloc").l should not be empty
          cpg.tag.name("untrusted-read").l should not be empty
          // every node carrying any memory tag also carries the umbrella
          val taggedNodes =
              cpg.call.filter(
                _.tag.name("mem-alloc|mem-free|mem-realloc|untrusted-read").l.nonEmpty
              ).l ++
                  cpg.call.flatMap(_.argument).filter(
                    _.tag.name("mem-dst|mem-src|mem-len|untrusted-read").l.nonEmpty
                  ).l
          taggedNodes.foreach { n =>
              n.tag.name.l should contain("memory-safety")
          }
      }

      "not tag anything that is not in the inventory" in {
          cpg.call.name("process").l shouldBe Nil // internal, not an API call site
          val taggedCallNames = cpg.call.filter(_.tag.name("memory-safety").l.nonEmpty).name.l.toSet
          // Call-level tags exist only where the inventory declares a call-level role
          // (alloc/free/realloc/untrusted-read). memcpy and snprintf are pure writers: their CALL
          // nodes carry no memory tag, only their arguments do - while snprintf's length argument
          // happens to be a sizeof() call, which is tagged in its argument role.
          taggedCallNames shouldBe Set(
            "malloc",
            "calloc",
            "realloc",
            "free",
            "read",
            "readlink",
            "<operator>.sizeOf"
          )
          call("memcpy").tag.name.l should not contain "memory-safety"
          call("memcpy").argument(1).tag.name.l should contain("memory-safety")
      }
  }

  "the declared region roles" should {

      "tag a region allocation with its region argument" in {
          val aprPalloc = regionCall("apr_palloc")
          aprPalloc.tag.name("mem-region").value.l shouldBe List("alloc:1")
          // the allocation family the entry declares travels beside the region
          aprPalloc.tag.name("mem-alloc").value.l shouldBe List("aprpool")
          aprPalloc.tag.name.l should contain("memory-safety")
      }

      "tag a create with the out-pointer that receives the region" in {
          regionCall("apr_pool_create").tag.name("mem-region").value.l shouldBe List("create:1")
      }

      "tag a reset and a destroy with the region they empty" in {
          regionCall("apr_pool_clear").tag.name("mem-region").value.l shouldBe List("reset:1")
          regionCall("apr_pool_destroy").tag.name("mem-region").value.l shouldBe List("destroy:1")
      }

      "tag a context-less allocation with the global it draws from" in {
          val palloc = regionCall("palloc")
          palloc.tag.name("mem-region").value.l shouldBe List("alloc:ctx:CurrentMemoryContext")
          palloc.tag.name("mem-alloc").value.l shouldBe List("pgmem")
      }

      "leave a release without a region role untagged" in {
          regionCall("pfree").tag.name.l should not contain "mem-region"
          regionCall("pfree").tag.name("mem-free").value.l shouldBe List("pgmem")
      }
  }

  "the declared reference roles" should {

      "tag the object a declared acquire takes a reference of" in {
          val keep = refCall("obj_keep")
          keep.tag.name("mem-acquire").value.l shouldBe List("1")
          keep.tag.name.l should contain("memory-safety")
          keep.tag.name.l should not contain "mem-release"
      }

      "tag the object a declared release drops a reference of" in {
          val drop = refCall("obj_drop")
          drop.tag.name("mem-release").value.l shouldBe List("1")
          drop.tag.name.l should contain("memory-safety")
          drop.tag.name.l should not contain "mem-free"
      }

      "tag the call sites of a body-concluded release like a declared one" in {
          inferredRefCpg.call.name("gref_unref").tag.name("mem-release").value.l shouldBe List(
            "1"
          )
      }

      "tag the call sites of a grow fact as the acquire" in {
          inferredRefCpg.call.name("gref_ref").tag.name("mem-acquire").value.l shouldBe List(
            "1"
          )
      }
  }

  "a profile entry's region roles" should {

      "not fire for a file that includes none of the profile's headers" in {
          val withoutHeader = code(
            """
            |void *apr_palloc(void *pool, unsigned long size);
            |
            |void *no_header_take(void *pool)
            |{
            |    return apr_palloc(pool, 16);
            |}
            |""".stripMargin,
            "no_apr_header.c"
          )
          new MemoryApiPass(withoutHeader).createAndApply()
          withoutHeader.call.name("apr_palloc").tag.name.l should not contain "mem-region"
          withoutHeader.call.name("apr_palloc").tag.name.l should not contain "mem-alloc"
      }

      "fire for the file that includes the profile's header" in {
          val headersDir = better.files.File(
            java.nio.file.Paths
                .get(getClass.getClassLoader.getResource("profiles/apr/apr_pools.h").toURI)
                .getParent
          )
          val withHeader = code(
            """
            |#include <apr_pools.h>
            |
            |void *header_take(apr_pool_t *pool)
            |{
            |    return apr_palloc(pool, 16);
            |}
            |""".stripMargin,
            "with_apr_header.c"
          ).withConfig(
            Config(includeComments = true).withIncludePaths(Set(headersDir.pathAsString))
          )
          new MemoryApiPass(withHeader).createAndApply()
          withHeader.call.name("apr_palloc").tag.name("mem-region").value.l shouldBe List(
            "alloc:1"
          )
      }
  }

  "MemApiVocab" should {

      "load the built-in inventory with every documented role present" in {
          val inv = MemApiVocab.builtInInventory.map(e => e.name -> e).toMap
          inv("bcopy").dst shouldBe Some(2) // bcopy(src, dst, n): reversed argument order
          inv("bcopy").src shouldBe Some(1)
          inv("getenv").untrustedCall shouldBe true
          inv("getenv").untrustedRead shouldBe None
          // realloc is the third family: neither an allocation nor a release
          inv("realloc").realloc shouldBe Some("heap")
          inv("realloc").alloc shouldBe None
          inv("realloc").free shouldBe None
          // count-by-size allocators declare both factors
          inv("calloc").count shouldBe Some(1)
          inv("calloc").len shouldBe Some(2)
          inv("reallocarray").count shouldBe Some(2)
          inv("reallocarray").len shouldBe Some(3)
          inv("<operator>.new").alloc shouldBe Some("new")
      }

      "merge an external config over the built-in inventory by name" in {
          val external = """{"version": 1, "apis": [
            {"name": "av_memcpy", "dst": 1, "src": 2, "len": 3},
            {"name": "memcpy", "dst": 4}
          ]}"""
          val inv      = MemApiVocab.inventory(Some(external))
          // a declared in-house wrapper tags without patching chen
          inv("av_memcpy").len shouldBe Some(3)
          // an external entry REPLACES the built-in one with the same name
          inv("memcpy").dst shouldBe Some(4)
          inv("memcpy").len shouldBe None
      }

      "ignore invalid external config rather than dropping the built-in inventory" in {
          val inv = MemApiVocab.inventory(Some("{not json"))
          inv("memcpy").dst shouldBe Some(1)
      }
  }
end MemoryApiPassTests
