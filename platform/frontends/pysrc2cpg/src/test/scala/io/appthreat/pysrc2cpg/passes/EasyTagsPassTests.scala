package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.shiftleft.semanticcpg.language.*

/** Regression tests for the false-positive-reduction tagging added to [[EasyTagsPass]] for Python:
 * literal-argument reflection suppression (G2), ORM `db-read` barrier tagging (G1), unsafe vs safe
 * (de)serialisation split (G5) and benign render/redirect output suppression (G3/G4).
 */
class EasyTagsPassTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def tagsOfCallContaining(cpg: io.shiftleft.codepropertygraph.Cpg, snippet: String): Set[String] =
      cpg.call.code(s".*${java.util.regex.Pattern.quote(snippet)}.*").tag.name.toSet

  "EasyTagsPass Python reflection (G2)" should:

    "not tag getattr with a literal attribute name as reflection" in:
        val cpg = code("""
            |def f(obj):
            |    return getattr(obj, "is_anonymous", False)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        tagsOfCallContaining(cpg, "getattr") should not contain "reflection"

    "tag getattr with a dynamic attribute name as reflection" in:
        val cpg = code("""
            |def f(obj, attr):
            |    return getattr(obj, attr)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        tagsOfCallContaining(cpg, "getattr") should contain("reflection")

  "EasyTagsPass Python ORM reads (G1)" should:

    "tag get_object_or_404 as db-read" in:
        val cpg = code("""
            |def f(pk):
            |    return get_object_or_404(Model, pk=pk)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        tagsOfCallContaining(cpg, "get_object_or_404") should contain("db-read")

    "tag a Model.objects.get accessor as db-read" in:
        val cpg = code("""
            |def f(pk):
            |    return Model.objects.get(id=pk)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        cpg.call.name("get").tag.name.toSet should contain("db-read")

  "EasyTagsPass Python (de)serialisation (G5)" should:

    "tag pickle.loads as unsafe-deserialization" in:
        val cpg = code("""
            |import pickle
            |def f(data):
            |    return pickle.loads(data)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        tagsOfCallContaining(cpg, "pickle.loads") should contain("unsafe-deserialization")

    "not tag json.loads as unsafe-deserialization" in:
        val cpg = code("""
            |import json
            |def f(data):
            |    return json.loads(data)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        tagsOfCallContaining(cpg, "json.loads") should not contain "unsafe-deserialization"

  "EasyTagsPass Python render/output (G3)" should:

    "not tag render with a method-resolved template as framework-output" in:
        val cpg = code("""
            |def view(self, request, context):
            |    return render(request, self.get_template(), context)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        cpg.call.name("render").tag.name.toSet should not contain "framework-output"

    "not tag render with a self.template member access as framework-output" in:
        val cpg = code("""
            |def view(self, request, context):
            |    return render(request, self.template, context)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        cpg.call.name("render").tag.name.toSet should not contain "framework-output"

  "EasyTagsPass Python ORM reads (G1, round 3)" should:

    "tag get_object_or_none as db-read and not framework-output" in:
        val cpg = code("""
            |def f(finding_id):
            |    return get_object_or_none(Finding, id=finding_id)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        val tags = cpg.call.name("get_object_or_none").tag.name.toSet
        tags should contain("db-read")
        tags should not contain "framework-output"

  "EasyTagsPass Python reflection (G2, round 3)" should:

    "not tag getattr with a self.<attr> attribute as reflection" in:
        val cpg = code("""
            |def f(self, finding):
            |    return getattr(finding, self.target_name)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        cpg.call.name("getattr").tag.name.toSet should not contain "reflection"

  "EasyTagsPass Python sanitizers (G6+)" should:

    "tag url_has_allowed_host_and_scheme as sanitization" in:
        val cpg = code("""
            |def f(url):
            |    return url_has_allowed_host_and_scheme(url, allowed_hosts=None)
            |""".stripMargin)
        new EasyTagsPass(cpg).createAndApply()
        cpg.call.name("url_has_allowed_host_and_scheme").tag.name.toSet should contain(
          "sanitization"
        )
