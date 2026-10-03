package io.appthreat.c2cpg.passes.ast

import io.appthreat.c2cpg.astcreation.Defines
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** An include's IMPORT node records the file the include resolved to, and whether it names a system
  * header, so a consumer can tell which package provides the header.
  */
class IncludeResolutionTests extends CCodeToCpgSuite:

  "an include" should {
      val cpg = code(
        """
          |#include "lib/api.h"
          |#include <no_such_system_header.h>
          |static int local_helper(void) { return 1; }
          |int main(void) { return api() + local_helper(); }
          |""".stripMargin,
        "main.c"
      ).moreCode("int api(void);\n", "lib/api.h")

      def importOf(entity: String) =
          cpg.imports.filter(_.file.name.headOption.exists(_.endsWith("main.c")))
              .importedEntity(entity).head

      "record the file it resolved to" in {
          val paths = importOf("lib/api.h").tag.nameExact(Defines.IncludeResolvedPathTag).value.l
          paths.size shouldBe 1
          paths.head.replace('\\', '/') should endWith("/lib/api.h")
          importOf("lib/api.h").tag.nameExact(Defines.IncludeSystemTag).size shouldBe 0
      }

      "make a call to a function the header declares name that header" in {
          val apiCall = cpg.call.nameExact("api").head
          val headers = apiCall.tag.nameExact(Defines.CalleeDeclaredInTag).value.l
          headers.size shouldBe 1
          headers.head.replace('\\', '/') should endWith("/lib/api.h")
          cpg.call.nameExact("local_helper").tag.nameExact(Defines.CalleeDeclaredInTag)
              .size shouldBe 0
      }

      "record a system include, and no path when it did not resolve" in {
          val system = importOf("no_such_system_header.h")
          system.tag.nameExact(Defines.IncludeSystemTag).value.l shouldBe List("true")
          system.tag.nameExact(Defines.IncludeResolvedPathTag).size shouldBe 0
      }
  }

  "a call written inside a macro" should {
      val cpg = code(
        """
          |#include "lib/api.h"
          |#define TWICE(x) ((x) * 2)
          |int main(void) { return TWICE(api()); }
          |""".stripMargin,
        "main.c"
      ).moreCode("int api(void);\n", "lib/api.h")

      "keep its header tag on the call the graph holds" in {
          val calls = cpg.call.nameExact("api").l
          // the argument copy and the call inside the expansion; the dropped original is not kept
          calls.size shouldBe 2
          calls.foreach(_._astIn.hasNext shouldBe true)
          calls.map(_.tag.nameExact(Defines.CalleeDeclaredInTag).size) shouldBe List(1, 1)
      }
  }
end IncludeResolutionTests
