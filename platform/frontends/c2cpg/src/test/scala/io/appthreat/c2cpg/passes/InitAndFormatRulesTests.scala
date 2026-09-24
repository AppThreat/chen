package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** MS-FMT-001 (CWE-134) and MS-INIT-001 (CWE-457). */
class InitAndFormatRulesTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdio.h>
    |#include <stdarg.h>
    |#include <syslog.h>
    |
    |void fmt_param(const char *u) { printf(u); }
    |void fmt_fprintf(const char *u) { fprintf(stderr, u); }
    |void fmt_snprintf(const char *u) { char b[8]; snprintf(b, sizeof(b), u); }
    |void fmt_syslog(const char *u) { syslog(LOG_INFO, u); }
    |void fmt_ok_literal(const char *u) { printf("%s", u); }
    |void fmt_local(const char *u) { const char *f = u; printf(f); }
    |void fmt_ok_local(int e) { const char *f = e ? "a %d" : "b %d"; printf(f, e); }
    |/* a forwarder: its callers' formats are what matters */
    |void my_log(const char *fmt, ...) { va_list vl; va_start(vl, fmt); vprintf(fmt, vl); va_end(vl); }
    |/* only ever called with literals */
    |static void say(const char *s) { printf(s); }
    |void callers(char **argv)
    |{
    |    say("hello\n");
    |    say("bye\n");
    |    fmt_param(argv[1]);
    |}
    |
    |int init_bad_scalar(void)
    |{
    |    int x;
    |    return x + 1;
    |}
    |struct S { int a; int b; };
    |int init_bad_field(void)
    |{
    |    struct S s;
    |    s.a = 1;
    |    return s.b;
    |}
    |int init_ok_field(void)
    |{
    |    struct S s;
    |    s.a = 1;
    |    return s.a;
    |}
    |#define GET_V(v, e) v = (e)
    |int init_ok_macro(int n)
    |{
    |    int x;
    |    GET_V(x, n + 1);
    |    return x;
    |}
    |int init_ok_av_uninit(int n)
    |{
    |    int x = x;
    |    if (n) x = 1;
    |    return n;
    |}
    |int init_ok_assigned(int n)
    |{
    |    int x;
    |    if (n) x = 1;
    |    else x = 2;
    |    return x;
    |}
    |int init_maybe(int n) /* one path initialises: not reported */
    |{
    |    int x;
    |    if (n) x = 1;
    |    return x;
    |}
    |int init_ok_out(void)
    |{
    |    int x;
    |    sscanf("1", "%d", &x);
    |    return x;
    |}
    |int init_ok_static(void)
    |{
    |    static int x;
    |    return x;
    |}
    |int init_ok_sizeof(void)
    |{
    |    int x;
    |    return (int)sizeof(x);
    |}
    |int init_ok_loop(int n)
    |{
    |    int x, i;
    |    for (i = 0; i < n; i++) {
    |        if (i)
    |            return x;
    |        x = i;
    |    }
    |    return 0;
    |}
    |int init_ok_whole(void)
    |{
    |    struct S s = {0};
    |    return s.b;
    |}
    |""".stripMargin,
    "rules.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.nameExact("ms-finding").value.l).l.toSet

  "MS-FMT-001" should:
    "report a non-constant format in each printf-family position" in {
        Seq("fmt_param", "fmt_fprintf", "fmt_snprintf", "fmt_syslog", "fmt_local").foreach { m =>
            withClue(m) { findingsIn(m) should contain("MS-FMT-001") }
        }
    }
    "leave literal, literal-only locals, forwarders and literal-only callers alone" in {
        Seq("fmt_ok_literal", "fmt_ok_local", "my_log", "say").foreach { m =>
            withClue(m) { findingsIn(m) should not contain "MS-FMT-001" }
        }
    }

  "MS-INIT-001" should:
    "report a local and a member no path initialises" in {
        findingsIn("init_bad_scalar") should contain("MS-INIT-001")
        findingsIn("init_bad_field") should contain("MS-INIT-001")
    }
    "leave initialised, out-param, static, sizeof, loop-carried and maybe-initialised reads alone" in {
        Seq(
          "init_ok_field",
          "init_ok_assigned",
          "init_maybe",
          "init_ok_out",
          "init_ok_static",
          "init_ok_sizeof",
          "init_ok_loop",
          "init_ok_whole",
          "init_ok_macro",
          "init_ok_av_uninit"
        ).foreach { m => withClue(m) { findingsIn(m) should not contain "MS-INIT-001" } }
    }
end InitAndFormatRulesTests
