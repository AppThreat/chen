package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Local}
import io.shiftleft.semanticcpg.language.*

/** The GCC `cleanup` attribute on C locals: the call `fn(&var)` the compiler makes wherever the
  * variable's scope ends, in the shape the other front end already emits. A cleanup call is a call
  * of the named function whose argument 1 is the variable's address, tagged `compiler-generated`
  * and `lifetime-end` with the variable's name. It runs where the block ends (on the line of the
  * block's closing bracket, where the EDG front end's graph of the same file places the call; the
  * bracket's line and the last statement's line coincide whenever the statement ends the block's
  * text), before every `return` in scope (the returned value is computed first when it observes the
  * variable), on a `goto` to a label outside the scope, and on a `break` or `continue` leaving a
  * loop body; inner scopes clean up first, and one scope's two variables in reverse declaration
  * order.
  *
  * The C forms live in a resource both front ends' suites read, so the same file can be compared
  * against the other front end's graph of it.
  */
class CleanupAttributeTests extends CCodeToCpgSuite:

  private val fixtureCode = new String(
    getClass.getResourceAsStream("/cleanup/scope_cleanup_forms.c").readAllBytes(),
    java.nio.charset.StandardCharsets.UTF_8
  )

  private lazy val cpg = code(fixtureCode, "scope_cleanup_forms.c")

  /** Every cleanup call of `method`, in the order its AST holds them. */
  private def cleanupsIn(method: String): List[Call] =
      cpg.method.nameExact(method).ast.isCall.l
          .filter(_.tag.nameExact(X2CpgDefines.LifetimeEndTag).l.nonEmpty)

  /** (line, name, code) of every cleanup call of `method`, in AST order. */
  private def cleanupFacts(method: String): List[(Int, String, String)] =
      cleanupsIn(method).map(c => (c.lineNumber.map(Integer2int).getOrElse(-1), c.name, c.code))

  "a cleanup call before an early return" should {
      "sit on the return's line, one per return, and none where the block ends after it" in {
          // three returns, three calls, each on its return's line; the block's last statement is
          // a return, so control never falls out of it and no fourth call is made
          cleanupFacts("plain_attribute_exits") shouldBe List(
            (77, "freep", "freep(&buf)"),
            (80, "freep", "freep(&buf)"),
            (81, "freep", "freep(&buf)")
          )
      }
      "reach the return as its CFG successor" in {
          // the return's own value expression (-1 is a literal a unary minus reads) sits between
          // the cleanup call and the RETURN node
          cleanupsIn("plain_attribute_exits").foreach { call =>
              (call.cfgNext.l ++ call.cfgNext.l.flatMap(_.cfgNext.l) ++
                  call.cfgNext.l.flatMap(_.cfgNext.l).flatMap(_.cfgNext.l)).label.l should
                  contain("RETURN")
          }
      }
  }

  "a cleanup call where a block ends" should {
      "take the line the block ends on" in {
          // the early return cleans up at line 89; control that falls out of the block instead
          // runs the cleanup where the block ends (its closing bracket, line 91)
          cleanupFacts("autofree_block_end") shouldBe List(
            (89, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&text)"),
            (91, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&text)")
          )
      }
  }

  "the g_autoptr spelling" should {
      "name the cleanup function its macro pastes, at each exit" in {
          cleanupFacts("autoptr_table") shouldBe List(
            (98, "glib_autoptr_cleanup_GHashTable", "glib_autoptr_cleanup_GHashTable(&table)"),
            (100, "glib_autoptr_cleanup_GHashTable", "glib_autoptr_cleanup_GHashTable(&table)")
          )
      }
  }

  "a return whose value observes the cleaned-up variable" should {
      "store the value before the cleanup call runs" in {
          // `return buf;` and `return buf[0];` observe buf: the value lands in a
          // compiler-generated <return-value> local first, then the cleanup runs, then the
          // local is returned
          // `return buf;` stores buf; `return buf[0];` stores the byte it reads
          Seq(
            ("return_of_cleaned_variable", 110, "<return-value> = buf"),
            ("return_reads_through", 120, "<return-value> = buf[0]")
          ).foreach { (method, line, stored) =>
            val call = cleanupsIn(method).filter(_.lineNumber.contains(line))
            call should have size 1
            // the cleanup call's own argument (&buf, and buf inside it) sits between the store
            // and the call in the CFG
            (call.head.cfgPrev.l ++ call.head.cfgPrev.l.flatMap(_.cfgPrev.l) ++
                call.head.cfgPrev.l.flatMap(_.cfgPrev.l).flatMap(_.cfgPrev.l)).code.l should
                contain(stored)
            (call.head.cfgNext.l ++ call.head.cfgNext.l.flatMap(_.cfgNext.l)).label.l should
                contain("RETURN")
          }
          cpg.method.nameExact("return_of_cleaned_variable").local.nameExact("<return-value>")
              .l should have size 1
          cpg.method.nameExact("return_reads_through").local.nameExact("<return-value>")
              .l should have size 1
          // the returns that do not observe buf keep the plain shape: no extra local
          cpg.method.nameExact("plain_attribute_exits").local.nameExact("<return-value>").l shouldBe empty
      }
  }

  "nested scopes and two variables in one scope" should {
      "clean up inner scopes first and variables in reverse declaration order" in {
          // return -1 (line 130) leaves the function scope: second, then first
          // return -2 (line 134) leaves the inner scope and the function scope: inner, second, first
          // the inner block ends at its closing bracket (line 137): inner
          // return (int)n (line 138) leaves the function scope: second, then first
          cleanupFacts("inner_first_and_reverse_order") shouldBe List(
            (130, "freep", "freep(&second)"),
            (130, "__free_kfree", "__free_kfree(&first)"),
            (134, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&inner)"),
            (134, "freep", "freep(&second)"),
            (134, "__free_kfree", "__free_kfree(&first)"),
            (137, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&inner)"),
            (138, "freep", "freep(&second)"),
            (138, "__free_kfree", "__free_kfree(&first)")
          )
      }
  }

  "a goto to a label outside the variable's scope" should {
      "clean up at the jump and where the block ends" in {
          // the goto at line 149 leaves the if-block that declares buf; the block's own end
          // (its closing bracket, line 152) cleans up where control falls out of it
          cleanupFacts("goto_leaving_nested") shouldBe List(
            (149, "__free_kfree", "__free_kfree(&buf)"),
            (152, "__free_kfree", "__free_kfree(&buf)")
          )
          cleanupsIn("goto_leaving_nested").head.cfgNext.code.l should contain("goto out;")
      }
  }

  "a goto whose label stays inside the variable's scope" should {
      "not clean up at the jump" in {
          // both gotos jump forward within the block that declares buf: the scope is not left
          // until the returns at the end clean it up
          cleanupFacts("goto_within_scope") shouldBe List(
            (172, "__free_kfree", "__free_kfree(&buf)"),
            (173, "__free_kfree", "__free_kfree(&buf)")
          )
      }
  }

  "a break and a continue leaving a loop body" should {
      "clean up at the jump and where the body's block ends" in {
          cleanupFacts("loop_break_continue") shouldBe List(
            (184, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&line)"),
            (186, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&line)"),
            (188, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&line)")
          )
          val byLine = cleanupsIn("loop_break_continue").groupBy(_.lineNumber.getOrElse(-1))
          byLine(184).head.cfgNext.code.l should contain("continue;")
          byLine(186).head.cfgNext.code.l should contain("break;")
          // where an iteration completes, the cleanup runs before the loop's update expression
          // takes the next iteration around: it stays inside the loop
          byLine(188).head.cfgNext.l.map(n => s"${n.label}:${n.code}") should contain(
            "IDENTIFIER:i"
          )
      }
  }

  "every cleanup call" should {
      "take the variable's address as argument 1, bound to the local in scope" in {
          val all = cpg.call.l.filter(_.tag.nameExact(X2CpgDefines.LifetimeEndTag).l.nonEmpty)
          all should have size 26
          all.foreach { call =>
            val variableName = call.tag.nameExact(X2CpgDefines.LifetimeEndTag).value.l.head
            val address = call.argument(1) match
              case c: Call => c
              case other   => fail(s"argument 1 of ${call.code} is not a call: $other")
            address.name shouldBe "<operator>.addressOf"
            address.code shouldBe s"&$variableName"
            val variable = address.argument(1) match
              case i: Identifier => i
              case other => fail(s"argument of ${address.code} is not an identifier: $other")
            variable.name shouldBe variableName
            cpg.identifier.id(variable.id).refsTo.collect { case l: Local => l.name }
                .l shouldBe List(variableName)
            call.tag.nameExact(X2CpgDefines.CompilerGeneratedTag).value.l shouldBe List("true")
          }
      }
      "resolve its function as a written call to that name resolves it" in {
          cpg.method.nameExact("plain_attribute_exits").call.nameExact("freep").methodFullName.l
              .distinct shouldBe List("freep")
          cpg.method.nameExact("return_of_cleaned_variable").call.nameExact("__free_kfree")
              .methodFullName.l.distinct shouldBe List("__free_kfree")
          cpg.method.nameExact("autoptr_table").call.nameExact("glib_autoptr_cleanup_GHashTable")
              .methodFullName.l.distinct shouldBe List("glib_autoptr_cleanup_GHashTable")
      }
      "not appear for a variable without the attribute" in {
          cpg.call.l
              .filter(
                _.tag.nameExact(X2CpgDefines.LifetimeEndTag).value("rc").l.nonEmpty
              ) shouldBe empty
          cpg.call.l
              .filter(
                _.tag.nameExact(X2CpgDefines.LifetimeEndTag).value("kept").l.nonEmpty
              ) shouldBe empty
      }
  }

  "a cleanup variable declared in a for statement's initializer" should {
      val cpg2 = code(
        """static void freep(void *p) { *(void **)p = 0; }
          |static size_t for_init_scope(size_t n)
          |{
          |    size_t total = 0;
          |    for (char *it __attribute__((cleanup(freep))) = malloc(n); it != NULL && total < 3; it = NULL) {
          |        total += 1;
          |    }
          |    return total;
          |}
          |""".stripMargin,
        "for_init_cleanup.c"
      )
      "clean up where the whole for statement ends" in {
          val calls = cpg2.method.nameExact("for_init_scope").ast.isCall.l
              .filter(_.tag.nameExact(X2CpgDefines.LifetimeEndTag).l.nonEmpty)
          calls should have size 1
          calls.head.code shouldBe "freep(&it)"
          // the for statement spans to the closing brace of its body (line 7)
          calls.head.lineNumber shouldBe Some(7)
      }
  }
end CleanupAttributeTests
