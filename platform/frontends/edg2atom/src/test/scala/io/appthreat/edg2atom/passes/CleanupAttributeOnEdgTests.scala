package io.appthreat.edg2atom.passes

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode, Identifier, Local}
import io.shiftleft.semanticcpg.language.*

/** The GCC `cleanup` attribute on C locals through this front end, over the same resource the
  * CDT-based front end's suite reads. Every cleanup call's name, argument, line, tags and CFG
  * successors are asserted here and compared with the calls the CDT front end makes on the same
  * file, so the two front ends agree on what the attribute does.
  */
class CleanupAttributeOnEdgTests extends EdgCodeToCpgSuite(".c"):

  private val fixtureCode = new String(
    getClass.getResourceAsStream("/cleanup/scope_cleanup_forms.c").readAllBytes(),
    java.nio.charset.StandardCharsets.UTF_8
  )

  private lazy val cpg = code(fixtureCode, "scope_cleanup_forms.c")

  private def cleanupFacts(graph: Cpg, method: String): List[(Int, String, String)] =
      graph.method.nameExact(method).ast.isCall.l
          .filter(_.tag.nameExact(X2CpgDefines.LifetimeEndTag).l.nonEmpty)
          .map(c => (c.lineNumber.map(Integer2int).getOrElse(-1), c.name, c.code))

  /** Every cleanup call of `method` with the normalised facts of its CFG predecessors and
    * successors. Normalised to what the two front ends spell alike: a jump keeps its statement's
    * text, an identifier keeps its code, a return keeps its label, and a value computation reads as
    * VALUE, because the front ends spell the same computation differently (the NULL macro is an
    * identifier in one graph and a call in the other, a cast is a TYPE_REF in one graph and an
    * UNKNOWN node in the other, and a literal is a literal in both). The neighbours form a set:
    * their order carries no compared fact.
    */
  private def neighbourFacts(
    graph: Cpg,
    method: String
  ): List[((Int, String, String), List[String], List[String])] =
      graph.method.nameExact(method).ast.isCall.l
          .filter(_.tag.nameExact(X2CpgDefines.LifetimeEndTag).l.nonEmpty)
          .map { c =>
            def fact(n: CfgNode): String = n.label match
              case "LITERAL" | "CALL" | "TYPE_REF" | "UNKNOWN" => "VALUE"
              case "IDENTIFIER" if n.code == "NULL"            => "VALUE"
              case "IDENTIFIER"                                => s"IDENTIFIER:${n.code}"
              case "CONTROL_STRUCTURE"                         => s"CONTROL_STRUCTURE:${n.code}"
              case other                                       => other
            (
              (c.lineNumber.map(Integer2int).getOrElse(-1), c.name, c.code),
              c.cfgPrev.l.map(fact).sorted,
              c.cfgNext.l.map(fact).sorted
            )
          }

  private def cleanupCalls(method: String): List[Call] =
      cpg.method.nameExact(method).ast.isCall.l
          .filter(_.tag.nameExact(X2CpgDefines.LifetimeEndTag).l.nonEmpty)

  /** The graph the CDT front end makes of the same file, built once and closed with the suite. */
  private var cdtGraph: Option[Cpg] = None

  private def cdtCpg: Cpg = cdtGraph.getOrElse {
      val dir = File.newTemporaryDirectory("cleanup-cdt")
      dir.deleteOnExit()
      (dir / "scope_cleanup_forms.c").writeText(fixtureCode)
      val out = File.newTemporaryFile("cleanup-cdt", ".bin")
      out.deleteOnExit()
      val config = Config()
          .withInputPath(dir.pathAsString)
          .withOutputPath(out.pathAsString)
          .withFunctionBodies(true)
          .withAstCache(false)
      val graph = new C2Cpg().createCpg(config).get
      // the suite's own graphs take the default overlays; the CFG the neighbours are read from is
      // one of them
      io.appthreat.x2cpg.X2Cpg.applyDefaultOverlays(graph)
      cdtGraph = Some(graph)
      graph
  }

  override def afterAll(): Unit =
    cdtGraph.foreach(_.close())
    super.afterAll()

  private val methods = List(
    "plain_attribute_exits",
    "autofree_block_end",
    "autoptr_table",
    "return_of_cleaned_variable",
    "return_reads_through",
    "inner_first_and_reverse_order",
    "goto_leaving_nested",
    "goto_within_scope",
    "loop_break_continue"
  )

  "the calls before each return" should {
      "sit on the return's line, one per return" in {
          requireEdga()
          cleanupFacts(cpg, "plain_attribute_exits") shouldBe List(
            (77, "freep", "freep(&buf)"),
            (80, "freep", "freep(&buf)"),
            (81, "freep", "freep(&buf)")
          )
      }
      "reach the return as their CFG successor" in {
          requireEdga()
          // the return's own value expression (the literal a unary minus reads) sits between the
          // cleanup call and the RETURN node
          cleanupCalls("plain_attribute_exits").foreach { call =>
              (call.cfgNext.l ++ call.cfgNext.l.flatMap(_.cfgNext.l) ++
                  call.cfgNext.l.flatMap(_.cfgNext.l).flatMap(_.cfgNext.l)).label.l should
                  contain("RETURN")
          }
      }
  }

  "the calls where a block ends and at each macro spelling" should {
      "match the exits of the g_autofree and g_autoptr spellings" in {
          requireEdga()
          cleanupFacts(cpg, "autofree_block_end") shouldBe List(
            (89, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&text)"),
            (91, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&text)")
          )
          cleanupFacts(cpg, "autoptr_table") shouldBe List(
            (98, "glib_autoptr_cleanup_GHashTable", "glib_autoptr_cleanup_GHashTable(&table)"),
            (100, "glib_autoptr_cleanup_GHashTable", "glib_autoptr_cleanup_GHashTable(&table)")
          )
      }
  }

  "the calls around returns that observe the variable" should {
      "run after the value is stored" in {
          requireEdga()
          Seq("return_of_cleaned_variable" -> 110, "return_reads_through" -> 120).foreach {
              (method, line) =>
                val call = cleanupCalls(method).filter(_.lineNumber.contains(line))
                call should have size 1
                // the return reads the stored local, not the cleaned-up variable
                call.head.cfgNext.l.map(n => s"${n.label}:${n.code}") should
                    contain("IDENTIFIER:<return-value>")
          }
      }
  }

  "the calls at jumps and loop bodies" should {
      "clean up inner scopes first, in reverse declaration order, at each exit" in {
          requireEdga()
          cleanupFacts(cpg, "inner_first_and_reverse_order") shouldBe List(
            (130, "freep", "freep(&second)"),
            (130, "__free_kfree", "__free_kfree(&first)"),
            (134, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&inner)"),
            (134, "freep", "freep(&second)"),
            (134, "__free_kfree", "__free_kfree(&first)"),
            (137, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&inner)"),
            (138, "freep", "freep(&second)"),
            (138, "__free_kfree", "__free_kfree(&first)")
          )
          cleanupFacts(cpg, "goto_leaving_nested") shouldBe List(
            (149, "__free_kfree", "__free_kfree(&buf)"),
            (152, "__free_kfree", "__free_kfree(&buf)")
          )
          cleanupFacts(cpg, "goto_within_scope") shouldBe List(
            (172, "__free_kfree", "__free_kfree(&buf)"),
            (173, "__free_kfree", "__free_kfree(&buf)")
          )
          cleanupFacts(cpg, "loop_break_continue") shouldBe List(
            (184, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&line)"),
            (186, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&line)"),
            (188, "g_autoptr_cleanup_generic_gfree", "g_autoptr_cleanup_generic_gfree(&line)")
          )
      }
      "reach the jump they precede, and stay inside the loop where the body ends" in {
          requireEdga()
          cleanupCalls("goto_leaving_nested")
              .filter(_.lineNumber.contains(149)).head.cfgNext.code.l should contain("goto out;")
          cleanupCalls("loop_break_continue")
              .filter(_.lineNumber.contains(184)).head.cfgNext.code.l should contain("continue;")
          cleanupCalls("loop_break_continue")
              .filter(_.lineNumber.contains(186)).head.cfgNext.code.l should contain("break;")
          cleanupCalls("loop_break_continue")
              .filter(_.lineNumber.contains(188)).head.cfgNext.l
              .map(n => s"${n.label}:${n.code}") should contain("IDENTIFIER:i")
      }
  }

  "every cleanup call" should {
      "take the variable's address as argument 1, bound to the local in scope, and carry the tags" in {
          requireEdga()
          val all = methods.flatMap(cleanupCalls)
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
            cpg.identifier.id(variable.id).refsTo.collect { case l: Local => l.name }.l shouldBe
                List(variableName)
            call.tag.nameExact(X2CpgDefines.CompilerGeneratedTag).value.l shouldBe List("true")
          }
      }
      "agree with the calls the CDT front end makes on the same file" in {
          requireEdga()
          methods.foreach { method =>
              withClue(method) {
                  cleanupFacts(cpg, method) shouldBe cleanupFacts(cdtCpg, method)
              }
          }
      }
      "agree with the CFG predecessors and successors of every cleanup call" in {
          requireEdga()
          methods.foreach { method =>
              withClue(method) {
                  neighbourFacts(cpg, method) shouldBe neighbourFacts(cdtCpg, method)
              }
          }
      }
  }

  "a cleanup variable declared in a for statement's initializer" should {
      val forInitCpg = code(
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
      "make no cleanup call in this front end's graph, where the loop ends" in {
          requireEdga()
          // the initializer's declaration records into the loop's own exit scope, and no emitter
          // consumes that scope where the loop ends normally, so this graph holds no call for it.
          // The CDT front end emits one call after the whole loop for the same source, which is
          // why this shape stays out of the fixture the two front ends are compared on.
          forInitCpg.method.nameExact("for_init_scope").ast.isCall.l
              .filter(_.tag.nameExact(X2CpgDefines.LifetimeEndTag).l.nonEmpty) shouldBe empty
      }
  }
end CleanupAttributeOnEdgTests
