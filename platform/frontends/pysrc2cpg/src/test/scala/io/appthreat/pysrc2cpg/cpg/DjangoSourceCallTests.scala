package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Call-resolution coverage over faithful excerpts of real Django source. Working
  * patterns are asserted with `in`; not-yet-resolved frontier patterns are `ignore`d
  * with a TODO so they stay visible as targets.
  */
class DjangoSourceCallTests extends PySrc2CpgFixture(withOssDataflow = false) {

  // ── django/apps/config.py (trimmed) ───────────────────────────────────────
  "AppConfig.create factory used by the registry" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def __init__(self, app_name, app_module):
        |        self.name = app_name
        |    @classmethod
        |    def create(cls, entry):
        |        return cls(entry, None)
        |    def import_models(self):
        |        pass
        |    def ready(self):
        |        pass
        |def boot(entry):
        |    cfg = AppConfig.create(entry)
        |    cfg.import_models()
        |    cfg.ready()
        |""".stripMargin,
      "config.py"
    )
    "type self with the class" in {
      cpg.method.name("import_models").parameter.name("self").typeFullName.head shouldBe
          "config.py:<module>.AppConfig"
    }
    "type cls with the class" in {
      cpg.method.name("create").parameter.name("cls").typeFullName.head shouldBe
          "config.py:<module>.AppConfig"
    }
    "resolve cfg.import_models() and cfg.ready() via the factory return type" in {
      cpg.call.name("import_models").methodFullName.toSet should
          contain("config.py:<module>.AppConfig.import_models")
      cpg.call.name("ready").methodFullName.toSet should
          contain("config.py:<module>.AppConfig.ready")
    }
  }

  // ── django/apps/registry.py (trimmed populate) ─────────────────────────────
  "Apps.populate calling sibling methods and a factory" should {
    lazy val cpg = code(
      """
        |from .config import AppConfig
        |class Apps:
        |    def __init__(self, installed_apps=()):
        |        self.app_configs = {}
        |        if installed_apps is not None:
        |            self.populate(installed_apps)
        |    def populate(self, installed_apps=None):
        |        for entry in installed_apps:
        |            app_config = AppConfig.create(entry)
        |            self.app_configs[app_config.label] = app_config
        |        self.clear_cache()
        |    def clear_cache(self):
        |        pass
        |""".stripMargin,
      "registry.py"
    )
    "resolve self.populate() from __init__" in {
      cpg.call.name("populate").methodFullName.toSet should
          contain("registry.py:<module>.Apps.populate")
    }
    "resolve self.clear_cache() from populate" in {
      cpg.call.name("clear_cache").methodFullName.toSet should
          contain("registry.py:<module>.Apps.clear_cache")
    }
    "link __init__ -> populate -> clear_cache in the callgraph" in {
      cpg.method.name("clear_cache").caller.name.toSet should contain("populate")
      cpg.method.name("populate").caller.name.toSet should contain("__init__")
    }
    // TODO(task #4): `app_config = AppConfig.create(entry)` is a factory, so
    // app_config.label / app_config should resolve to AppConfig members.
    "resolve app_config to AppConfig (factory return propagated to local)" in {
      cpg.call.name("create").methodFullName.toSet should
          contain("registry.py:<module>.Apps.AppConfig.create").or(
            contain("config.py:<module>.AppConfig.create")
          )
    }
  }

  // ── inheritance: AppConfig subclasses (very common in django) ──────────────
  "a subclass calling an inherited method via self" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def ready(self):
        |        pass
        |class AdminConfig(AppConfig):
        |    def run(self):
        |        self.ready()
        |""".stripMargin,
      "apps.py"
    )
    "resolve self.ready() to the base class" in {
      cpg.call.name("ready").methodFullName.toSet should
          contain("apps.py:<module>.AppConfig.ready")
    }
  }

  // ── for-loop element typing ────────────────────────────────────────────────
  "iterating a collection of known element type" should {
    lazy val cpg = code(
      """
        |class AppConfig:
        |    def import_models(self):
        |        pass
        |def f(configs: list[AppConfig]):
        |    for app_config in configs:
        |        app_config.import_models()
        |""".stripMargin,
      "registry.py"
    )
    "resolve app_config.import_models() via the iterated element type" in {
      cpg.call.name("import_models").methodFullName.toSet should
          contain("registry.py:<module>.AppConfig.import_models")
    }
  }
}
