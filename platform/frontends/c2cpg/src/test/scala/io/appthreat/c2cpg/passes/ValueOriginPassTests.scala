package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{MemoryApiPass, ValueOriginPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** ValueOriginPass: one fixture per origin, `mixed` where a length is a clamp of two origins, and
  * `unknown` where nothing is derivable - computed from REACHING_DEF edges, not a `df` solve.
  */
class ValueOriginPassTests extends DataFlowCodeToCpgSuite:

  private val cpg: Cpg = code(
    """
    |#include <string.h>
    |#include <stdlib.h>
    |#include <unistd.h>
    |
    |struct db { unsigned char *payload; int payload_len; };
    |
    |int next_len(void);
    |
    |int caller_param(unsigned char *d, const unsigned char *s, int size) {
    |    memcpy(d, s, size);
    |    return 0;
    |}
    |
    |int from_read(unsigned char *d, unsigned char *tmp, int fd) {
    |    int n = read(fd, tmp, sizeof(tmp));
    |    memcpy(d, tmp, n);
    |    return n;
    |}
    |
    |int constant_len(unsigned char *d, const unsigned char *s) {
    |    memcpy(d, s, 64);
    |    return 0;
    |}
    |
    |unsigned char *alloc_constant(void) {
    |    unsigned char *p = malloc(128);
    |    memset(p, 0, 128);
    |    return p;
    |}
    |
    |int struct_field(unsigned char *d, struct db *b) {
    |    memcpy(d, b->payload, b->payload_len);
    |    return 0;
    |}
    |
    |int mixed_origin(unsigned char *d, struct db *b, int size) {
    |    int n = b->payload_len < size ? b->payload_len : size;
    |    memcpy(d, b->payload, n);
    |    return n;
    |}
    |
    |int clobbered_param(unsigned char *d, struct db *b, int size) {
    |    size = b->payload_len;
    |    memcpy(d, b->payload, size);
    |    return size;
    |}
    |
    |int unknown_origin(unsigned char *d, const unsigned char *s) {
    |    memcpy(d, s, next_len());
    |    return 0;
    |}
    |
    |void index_param(unsigned char *buf, int i) {
    |    buf[i] = 0;
    |}
    |""".stripMargin,
    "origin.c"
  )

  new MemoryApiPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()

  private def lenTags(method: String): Set[String] =
      cpg.method
          .name(method)
          .call
          .name("memcpy")
          .l
          .flatMap(_.argument.l.filter(a => a.tag.name("mem-len").l.nonEmpty))
          .flatMap(_.tag.name.l)
          .toSet

  private def lenOrigin(method: String): String =
      cpg.method
          .name(method)
          .call
          .name("memcpy")
          .l
          .flatMap(_.argument.l.filter(a => a.tag.name("mem-len").l.nonEmpty))
          .flatMap(_.tag.name("origin").value.l)
          .head

  private def indexTags: Set[String] =
      cpg.call
          .name("<operator>.indirectIndexAccess|<operator>.indexAccess")
          .l
          .flatMap(_.argument.l)
          .filter(a => a.tag.name("origin").l.nonEmpty)
          .flatMap(_.tag.name.l)
          .toSet

  "ValueOriginPass" should {

      "tag a length used straight from a parameter as caller-param" in {
          lenOrigin("caller_param") shouldBe "caller-param"
          lenTags("caller_param") should contain("caller-param")
          lenTags("caller_param") should contain("origin")
          lenTags("caller_param") should contain("memory-safety")
      }

      "tag a length defined by an untrusted reader as untrusted-read" in {
          lenOrigin("from_read") shouldBe "untrusted-read"
      }

      "tag a literal length as constant" in {
          lenOrigin("constant_len") shouldBe "constant"
      }

      "tag a length read from a struct as struct-field" in {
          lenOrigin("struct_field") shouldBe "struct-field"
      }

      "tag a clamped length of two origins as mixed" in {
          lenOrigin("mixed_origin") shouldBe "mixed"
      }

      "see the param's death: a clobbered capacity parameter is struct-field, not caller-param" in {
          // size = b->payload_len kills the parameter's definition; the copy's length is the field
          lenOrigin("clobbered_param") shouldBe "struct-field"
          lenTags("clobbered_param") should not contain "caller-param"
      }

      "tag nothing derivable as unknown rather than guessing" in {
          lenOrigin("unknown_origin") shouldBe "unknown"
      }

      "tag array indices too" in {
          indexTags should contain("caller-param")
          indexTags should contain("origin")
      }

      "emit origin on mem-alloc size arguments as well" in {
          // malloc's size argument carries mem-len, so it gets an origin like any other length
          cpg.call
              .name("malloc")
              .l
              .flatMap(_.argument.l.filter(a => a.tag.name("mem-len").l.nonEmpty))
              .flatMap(_.tag.name("origin").value.l) shouldBe List("constant")
      }
  }
end ValueOriginPassTests
