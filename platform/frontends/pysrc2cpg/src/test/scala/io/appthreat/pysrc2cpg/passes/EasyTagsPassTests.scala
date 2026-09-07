package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.shiftleft.semanticcpg.language.*
import org.scalatest.prop.TableDrivenPropertyChecks.*

/** Regression tests for the false-positive-reduction tagging added to [[EasyTagsPass]] for Python:
  * literal-argument reflection suppression (G2), ORM `db-read` barrier tagging (G1), unsafe vs safe
  * (de)serialisation split (G5) and benign render/redirect output suppression (G3/G4).
  */
class EasyTagsPassTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def tagsOfCallContaining(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    snippet: String
  ): Set[String] =
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

  /** Once dependency bodies are in the graph (`python-deps=full`) a sink call resolves to the
    * module that really defines it - `subprocess/__init__.py`, `requests/api.py` - not to the
    * single-file `pkg.fn` spelling the thin modes produce. The sink patterns have to accept a
    * module inside the package, and the near-miss is what keeps that from becoming a wildcard: the
    * package name must still end at a path separator or the extension.
    */
  "EasyTagsPass Python sink module paths" should:

    "tag a sink defined in a module inside the package" in:
      val cpg = code(
        """
              |from subprocess.compat import run
              |
              |def f(cmd):
              |    return run(cmd)
              |""".stripMargin,
        "app.py"
      )
          .moreCode(
            """def run(cmd):
                  |    return cmd
                  |""".stripMargin,
            "subprocess/compat.py"
          )
      new EasyTagsPass(cpg).createAndApply()
      cpg.call.name("run").tag.name.toSet should contain("code-execution")

    "not tag a same-prefixed package that merely starts with a sink module's name" in:
      val cpg = code(
        """
              |from subprocessing.utils import run
              |
              |def f(cmd):
              |    return run(cmd)
              |""".stripMargin,
        "app.py"
      )
          .moreCode(
            """def run(cmd):
                  |    return cmd
                  |""".stripMargin,
            "subprocessing/utils.py"
          )
      new EasyTagsPass(cpg).createAndApply()
      cpg.call.name("run").tag.name.toSet should not contain "code-execution"

  /** P.2 prefilter safety: every sink family whose regex is now wrapped in a `PrefilteredRegex`
    * must still tag its call. Each case names the family and a call that the regex accepted before
    * the prefilter; a literal group narrower than its pattern drops the tag here. Families whose
    * full-name pattern only fires in dotted mode (socket, ssl, net-protocol, shutil) are covered by
    * [[EasyTagsPassDottedPrefilterTests]].
    */
  "EasyTagsPass Python prefiltered sink families (P.2)" should:

    val families = Table(
      ("family", "snippet", "tag"),
      (
        "deserialization",
        """def f(data):
          |    import marshal
          |    return marshal.loads(data)
          |""".stripMargin,
        "unsafe-deserialization"
      ),
      (
        "crypto-lib",
        """def f(k):
          |    from cryptography.fernet import Fernet
          |    return Fernet(k)
          |""".stripMargin,
        "crypto"
      ),
      (
        "code-execution-code",
        """def f(c):
          |    import os
          |    return os.popen(c)
          |""".stripMargin,
        "code-execution"
      ),
      (
        "shell-exec",
        """def f(c):
          |    import subprocess
          |    subprocess.run(c, shell=True)
          |""".stripMargin,
        "shell-exec"
      ),
      (
        "ssrf-code-dynamic",
        """def f(u):
          |    import requests
          |    return requests.get(u, timeout=1)
          |""".stripMargin,
        "ssrf"
      ),
      (
        "ldap-code",
        """def f(u):
          |    import ldap
          |    return ldap.initialize(u)
          |""".stripMargin,
        "ldap"
      ),
      (
        "xxe-code",
        """def f(x):
          |    from lxml import etree
          |    return etree.fromstring(x)
          |""".stripMargin,
        "xxe"
      ),
      (
        "db-read-helper",
        """def f(pk):
          |    return get_object_or_404(pk)
          |""".stripMargin,
        "db-read"
      )
    )

    "still tag every prefiltered family's call" in:
      forEvery(families) { (_, snippet, expectedTag) =>
        val cpg = code(snippet)
        new EasyTagsPass(cpg).createAndApply()
        withClue(s"snippet:\n$snippet\n") {
            cpg.call.tag.name.toSet should contain(expectedTag)
        }
      }

    "still not tag near-miss families after the prefilter" in:
      val cpg = code("""
            |def f(a, b):
            |    return socketry.connect(a, b)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      cpg.call.tag.name.toSet should not contain "network"
end EasyTagsPassTests

/** The dotted half of the P.2 prefilter safety net: `socket.socket()`, `ssl.*` etc. only resolve to
  * full names their regex accepts in dotted form, which is now the only form.
  */
class EasyTagsPassDottedPrefilterTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def tagsOfFirstCall(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    callName: String
  ): Set[String] =
      cpg.call.name(callName).tag.name.toSet

  "EasyTagsPass dotted-mode prefiltered families (P.2)" should:

    "tag socket.socket as network" in:
      val cpg = code("""
            |def f(h):
            |    import socket
            |    return socket.socket()
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOfFirstCall(cpg, "socket") should contain("network")

    "tag ssl.create_default_context as network" in:
      val cpg = code("""
            |def f(host):
            |    import ssl
            |    return ssl.create_default_context()
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOfFirstCall(cpg, "create_default_context") should contain("network")

    "tag shutil.copy as file-io" in:
      val cpg = code("""
            |def f(src, dst):
            |    import shutil
            |    shutil.copy(src, dst)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOfFirstCall(cpg, "copy") should contain("file-io")

    "tag json.loads as serialization" in:
      val cpg = code("""
            |def f(s):
            |    import json
            |    return json.loads(s)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOfFirstCall(cpg, "loads") should contain("serialization")

    "tag re.compile as regex" in:
      val cpg = code("""
            |def f(s):
            |    import re
            |    return re.compile(s)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOfFirstCall(cpg, "compile") should contain("regex")

    "tag importlib.import_module as reflection" in:
      val cpg = code("""
            |def f(m):
            |    import importlib
            |    return importlib.import_module(m)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOfFirstCall(cpg, "import_module") should contain("reflection")

    "tag threading.Thread as concurrent" in:
      val cpg = code("""
            |def f(fn):
            |    import threading
            |    return threading.Thread(target=fn)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOfFirstCall(cpg, "Thread") should contain("concurrent")

    "tag Crypto AES.new as crypto-generate" in:
      val cpg = code("""
            |def f(key):
            |    from Crypto.Cipher import AES
            |    return AES.new(key)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOfFirstCall(cpg, "new") should contain("crypto-generate")

    "tag subprocess.run resolved in dotted mode as code-execution" in:
      val cpg = code(
        """from subprocess import run
          |
          |def f(cmd):
          |    return run(cmd)
          |""".stripMargin,
        "app.py"
      ).moreCode(
        """def run(cmd):
          |    return cmd
          |""".stripMargin,
        "subprocess.py"
      )
      new EasyTagsPass(cpg).createAndApply()
      cpg.call.name("run").tag.name.toSet should contain("code-execution")
end EasyTagsPassDottedPrefilterTests
