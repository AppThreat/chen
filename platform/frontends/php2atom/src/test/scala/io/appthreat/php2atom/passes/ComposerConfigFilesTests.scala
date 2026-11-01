package io.appthreat.php2atom.passes

import better.files.File
import io.appthreat.php2atom.{Config, Php2Atom}
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.util.Try

/** Composer's installed-package record and autoload maps are config files of the graph, so the
  * callsites slice can map a class to its package while `vendor/` itself is not parsed; the
  * `composer.json` files of the packages inside `vendor/` are still not.
  */
class ComposerConfigFilesTests extends AnyWordSpec with Matchers:

  "the config file pass" should {
      "include the Composer metadata of the vendor directory next to the other config files" in {
          val dir = File.newTemporaryDirectory("composer-config-files-")
          try
            (dir / "src").createDirectories()
            (dir / "src" / "A.php").writeText("<?php class A {}")
            (dir / "composer.json").writeText("{}")
            (dir / "vendor" / "composer").createDirectories()
            for name <- List(
                "installed.json",
                "autoload_classmap.php",
                "autoload_psr4.php",
                "autoload_namespaces.php",
                "autoload_real.php"
              )
            do (dir / "vendor" / "composer" / name).writeText("x")
            (dir / "vendor" / "acme" / "pkg").createDirectories()
            (dir / "vendor" / "acme" / "pkg" / "package.yaml").writeText("x")
            (dir / "other" / "installed.json").createFileIfNotExists(createParents = true)

            val cpg =
                new Php2Atom().createCpg(Config().withInputPath(dir.pathAsString).withOutputPath(
                  (dir / "out.atom").pathAsString
                )).get
            try
                cpg.configFile.name.l.map(_.replace('\\', '/')).sorted shouldBe List(
                  "composer.json",
                  "vendor/acme/pkg/package.yaml",
                  "vendor/composer/autoload_classmap.php",
                  "vendor/composer/autoload_namespaces.php",
                  "vendor/composer/autoload_psr4.php",
                  "vendor/composer/installed.json"
                )
            finally cpg.close()
          finally Try(dir.delete(swallowIOExceptions = true))
          end try
      }
  }
end ComposerConfigFilesTests
