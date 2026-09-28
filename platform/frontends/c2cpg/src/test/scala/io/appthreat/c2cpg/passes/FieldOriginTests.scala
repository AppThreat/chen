package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.semanticcpg.language.*

/** Where a length read out of a struct field came from: a value the method stored into it, bytes an
  * untrusted read filled, or - when neither is established - the struct itself.
  */
class FieldOriginTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <string.h>
    |#include <unistd.h>
    |struct msg { unsigned len; };
    |struct hdr { unsigned short len; unsigned short kind; };
    |void update(struct msg *m);
    |
    |void stored_from_the_caller(char *d, const char *s, unsigned n)
    |{
    |    struct msg m;
    |    m.len = n;
    |    memcpy(d, s, m.len);
    |}
    |
    |void stored_then_handed_away(char *d, const char *s, unsigned n)
    |{
    |    struct msg m;
    |    m.len = n;
    |    update(&m);
    |    memcpy(d, s, m.len);
    |}
    |
    |void header_overlaid_on_a_read(int fd, char *d)
    |{
    |    char buf[512];
    |    read(fd, buf, sizeof(buf));
    |    struct hdr *h = (struct hdr *)buf;
    |    memcpy(d, buf + 4, h->len);
    |}
    |
    |void header_read_into_a_struct(int fd, char *d, const char *s)
    |{
    |    struct hdr h;
    |    read(fd, &h, sizeof(h));
    |    memcpy(d, s, h.len);
    |}
    |
    |void plain_field(char *d, const char *s, struct msg *m)
    |{
    |    memcpy(d, s, m->len);
    |}
    |""".stripMargin,
    "fieldorigin.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()

  private def originOfCopyLength(method: String): List[String] =
      cpg.method.nameExact(method).call.nameExact("memcpy").argument.argumentIndex(3)
          .flatMap(_.tag.name(ValueOriginPass.TagOrigin).value.l).l

  "a field length" should:
    "carry the origin of the value the method stored into it" in {
        originOfCopyLength("stored_from_the_caller") shouldBe List(
          ValueOriginPass.OriginCallerParam
        )
    }
    "not claim the stored value once a call may have rewritten the struct" in {
        originOfCopyLength("stored_then_handed_away") shouldBe List(
          ValueOriginPass.OriginStructField
        )
    }
    "be untrusted when read out of bytes an untrusted read filled" in {
        originOfCopyLength("header_overlaid_on_a_read") shouldBe List(
          ValueOriginPass.OriginUntrustedRead
        )
        originOfCopyLength("header_read_into_a_struct") shouldBe List(
          ValueOriginPass.OriginUntrustedRead
        )
    }
    "stay a struct field otherwise" in {
        originOfCopyLength("plain_field") shouldBe List(ValueOriginPass.OriginStructField)
    }
end FieldOriginTests
