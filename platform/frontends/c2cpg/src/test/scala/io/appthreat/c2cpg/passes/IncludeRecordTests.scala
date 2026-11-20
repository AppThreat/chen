package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.astcreation.Defines
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** The `#include` record: each translation unit's primary source file carries one `includes` tag
  * per header it includes, valued with the header's basename. A header this front end parses as a
  * unit of its own carries its own includes, never those of a unit that includes it, and an include
  * in a branch the preprocessor skipped is not recorded.
  */
class IncludeRecordTests extends CCodeToCpgSuite:

  private val cpg = code(
    """
      |#include <stdio.h>
      |#include "lib/api.h"
      |#include <no_such_system_header.h>
      |#include "lib/api.h"
      |#if 0
      |#include <glib.h>
      |#endif
      |#ifdef NO_SUCH_CONFIGURATION_MACRO
      |#include <linux/slab.h>
      |#endif
      |
      |int main(void) { return api(); }
      |""".stripMargin,
    "main.c"
  ).moreCode("#include <stddef.h>\nint api(void);\n", "lib/api.h")

  "the include record" should {

      "tag the unit's FILE node with the basename of each header it includes" in {
          val main = cpg.file.name("main.c").l
          main should have size 1
          main.head.tag.nameExact(Defines.IncludesTag).value.l
              .sorted shouldBe List("api.h", "no_such_system_header.h", "stdio.h")
      }

      "record an include the include path never resolved, by its spelling" in {
          // a library header the include path does not carry is the normal case for the headers
          // that select a profile; the unit still spelled it
          cpg.file.name("main.c").tag.nameExact(Defines.IncludesTag).value.l should contain(
            "no_such_system_header.h"
          )
      }

      "record each header once" in {
          cpg.file.name("main.c").tag
              .nameExact(Defines.IncludesTag).value.l.filter(_ == "api.h").size shouldBe 1
      }

      "give a header's own FILE node its own includes and not the unit's" in {
          // the FILE name uses the platform's separator (lib\api.h on Windows)
          val header = cpg.file.filter(_.name.replace('\\', '/') == "lib/api.h").l
          header should have size 1
          header.tag.nameExact(Defines.IncludesTag).value.l shouldBe List("stddef.h")
      }

      "skip an include in a branch the preprocessor did not take" in {
          val recorded = cpg.file.name("main.c").tag.nameExact(Defines.IncludesTag).value.l
          recorded should not contain "glib.h"
          recorded should not contain "slab.h"
      }
  }
end IncludeRecordTests
