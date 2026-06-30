package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Call-resolution tests modelled on actual Django source (django/apps/registry.py).
  * These reproduce real-world patterns (self-calls nested in `with`/`for`/`if`, calls
  * made from `__init__`) that the simplified SelfCallResolutionTests did not cover.
  */
class DjangoCallResolutionTests extends PySrc2CpgFixture(withOssDataflow = false) {

  // Trimmed-but-faithful excerpt of django/apps/registry.py
  lazy val cpg = code(
    """
      |import threading
      |
      |class Apps:
      |    def __init__(self, installed_apps=()):
      |        self.app_configs = {}
      |        self._lock = threading.RLock()
      |        self.ready = False
      |        if installed_apps is not None:
      |            self.populate(installed_apps)
      |
      |    def populate(self, installed_apps=None):
      |        if self.ready:
      |            return
      |        with self._lock:
      |            if self.ready:
      |                return
      |            for entry in installed_apps:
      |                self.check_apps_ready()
      |            self.clear_cache()
      |
      |    def check_apps_ready(self):
      |        pass
      |
      |    def clear_cache(self):
      |        pass
      |""".stripMargin,
    "registry.py"
  )

  "the self parameter of populate" should {
    "be typed with the enclosing class" in {
      cpg.method.name("populate").parameter.name("self").typeFullName.head shouldBe
          "registry.py:<module>.Apps"
    }
  }

  "self.clear_cache() nested inside a with-block" should {
    "resolve to the class method" in {
      val call = cpg.call.code("self.clear_cache.*").name("clear_cache").head
      call.methodFullName shouldBe "registry.py:<module>.Apps.clear_cache"
    }
  }

  "self.check_apps_ready() nested inside with+for" should {
    "resolve to the class method" in {
      val call = cpg.call.name("check_apps_ready").head
      call.methodFullName shouldBe "registry.py:<module>.Apps.check_apps_ready"
    }
  }

  "self.populate() called from __init__" should {
    "resolve to the class method" in {
      val call = cpg.call.name("populate").head
      call.methodFullName shouldBe "registry.py:<module>.Apps.populate"
    }
  }

  "the callgraph" should {
    "link populate -> clear_cache" in {
      cpg.method.name("clear_cache").caller.name.toSet should contain("populate")
    }
    "link __init__ -> populate" in {
      cpg.method.name("populate").caller.name.toSet should contain("__init__")
    }
  }
}
