package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.language.toExtendedCfgNode
import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.shiftleft.semanticcpg.language.*

/** PEP 750 t-strings, CPG side (Task 10 A, renderer half closed by Task 12 D.1). Two things are
  * asserted per the task's quality bar: the AST SHAPE (a t-string is a `<operator>.templateString`
  * call whose interpolations are `<operator>.interpolation` calls - not an opaque Unknown and not a
  * formatString), and the security semantics that make t-strings worth having (an f-string IS its
  * concatenation, a t-string is not: nothing flows from an interpolation into the literal's result
  * \- unless a renderer consumes the template, which the `PythonTemplateRenderPass` bridge edges
  * carry, `str(t"…")` being the canonical renderer).
  */
class Py314TemplateStringTests extends PySrc2CpgFixture(withOssDataflow = true):

  "the CPG shape of a t-string" should {

      "be a templateString call holding literals and interpolation calls" in {
          val cpg = code("""
            |def f(col):
            |    return t"select {col} from t"
            |""".stripMargin)
          val template = cpg.call.name("<operator>.templateString").l
          template should have size 1
          template.head.code shouldBe "t\"select {col} from t\""

          val interpolations = cpg.call.name("<operator>.interpolation").l
          interpolations should have size 1
          interpolations.head.code shouldBe "{col}"
          // The value expression is a real argument, so the flow engine can see INTO the
          // interpolation - it is evaluated, only the substitution is deferred.
          interpolations.head.argument.isIdentifier.name("col").size shouldBe 1

          // And it is NOT lowered as an f-string concatenation.
          cpg.call.name("<operator>.formatString").size shouldBe 0
      }

      "keep the f-string lowering unchanged" in {
          val cpg = code("""
            |def f(col):
            |    return f"select {col} from t"
            |""".stripMargin)
          cpg.call.name("<operator>.formatString").size shouldBe 1
          cpg.call.name("<operator>.formattedValue").size shouldBe 1
          cpg.call.name("<operator>.templateString").size shouldBe 0
      }

      "tag the template and its interpolations template-literal (and NOT sanitization)" in {
          val cpg = code("""
            |def f(col):
            |    return t"select {col} from t"
            |""".stripMargin)
          new EasyTagsPass(cpg).createAndApply()
          cpg.call.name("<operator>.templateString").tag.name.toSet should contain(
            "template-literal"
          )
          cpg.call.name("<operator>.interpolation").tag.name.toSet should
              contain("template-literal")
          // The deferral is not a declassification.
          cpg.call.name("<operator>.templateString").tag.name.toSet should not contain
              "sanitization"
      }
  }

  "the interpolation boundary" should {

      def flowsFor(literal: String): Int =
        val cpg = code(s"""
            |def handler(col):
            |    import os
            |    os.system($literal)
            |""".stripMargin)
        val source = cpg.identifier.name("col")
        val sink   = cpg.call.name("system").argument
        sink.reachableByFlows(source).size

      "report the flow through an f-string concatenation" in {
          // The control: with f-strings the interpolation IS a concatenation and taints the
          // result, so the source reaches the sink.
          flowsFor("""f"ls {col}"""") should be > 0
      }

      "not report the flow through a t-string at the interpolation" in {
          // The point of PEP 750: the interpolations are held unevaluated in the Template
          // object; nothing is substituted into a string, so the flow stops at the boundary.
          flowsFor("""t"ls {col}"""") shouldBe 0
      }

      "report through a str() renderer (task 12 D.1 closed the limit)" in {
          // In the real language str(tpl) renders the template and the taint escapes; the
          // PythonTemplateRenderPass bridges each interpolation's value to the renderer call,
          // so the flow reports. Both halves hold: the boundary above, the renderer here.
          flowsFor("""str(t"ls {col}")""") should be > 0
      }

      "not bridge through a variable-indirect template (the precise D.1 boundary)" in {
          val cpg = code(s"""
              |def handler(col):
              |    from string import Template
              |    tpl = Template(t"hi {col}")
              |    out = tpl.substitute()
              |    import os
              |    os.system(out)
              |""".stripMargin)
          // The bridge fires only when a renderer consumes a LITERAL templateString argument;
          // through a bound variable the engine sees an opaque substitute() call whose argument
          // carries no taint, so nothing reports. The honest boundary, asserted as such.
          val source = cpg.identifier.name("col")
          val sink   = cpg.call.name("system").argument
          sink.reachableByFlows(source).size shouldBe 0
          // The deferral is not a declassification, whatever the consumer.
          cpg.call.name("<operator>.templateString").tag.name.toSet should not contain "sanitization"
      }
  }
end Py314TemplateStringTests
