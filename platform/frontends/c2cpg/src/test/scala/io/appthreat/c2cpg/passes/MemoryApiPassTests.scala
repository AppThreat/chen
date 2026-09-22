package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{MemApiVocab, MemoryApiPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

/** MemoryApiPass: tags only - roles come from the inventory, arguments get the tags, every
  * fine-grained tag travels with the `memory-safety` umbrella. The C2 inference concludes wrapper
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
    |    memcpy(buf, src, n);
    |    snprintf(buf, sizeof(buf), "%s", src);
    |    read(fd, buf, n);
    |    free(heap);
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

  "MemoryApiPass" should {

      "tag the roles of memcpy's arguments by index from the inventory" in {
          val memcpy = call("memcpy")
          memcpy.argument(1).tag.name.l should contain("mem-dst")
          memcpy.argument(2).tag.name.l should contain("mem-src")
          memcpy.argument(3).tag.name.l should contain("mem-len")
          // value = the API name, so a consumer can tell which API put the tag there
          memcpy.argument(3).tag.name("mem-len").value.l shouldBe List("memcpy")
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
          cpg.tag.name("untrusted-read").l should not be empty
          // every node carrying any memory tag also carries the umbrella
          val taggedNodes =
              cpg.call.filter(_.tag.name("mem-alloc|mem-free|untrusted-read").l.nonEmpty).l ++
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
          // (alloc/free/untrusted-read). memcpy and snprintf are pure writers: their CALL nodes
          // carry no memory tag, only their arguments do - while snprintf's length argument
          // happens to be a sizeof() call, which is tagged in its argument role.
          taggedCallNames shouldBe Set("malloc", "free", "read", "readlink", "<operator>.sizeOf")
          call("memcpy").tag.name.l should not contain "memory-safety"
          call("memcpy").argument(1).tag.name.l should contain("memory-safety")
      }
  }

  "MemApiVocab" should {

      "load the built-in inventory with every documented role present" in {
          val inv = MemApiVocab.builtInInventory.map(e => e.name -> e).toMap
          inv("bcopy").dst shouldBe Some(2) // bcopy(src, dst, n): reversed argument order
          inv("bcopy").src shouldBe Some(1)
          inv("getenv").untrustedCall shouldBe true
          inv("getenv").untrustedRead shouldBe None
          inv("realloc").alloc shouldBe Some("heap")
          inv("realloc").free shouldBe Some("heap") // realloc releases its input too
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
