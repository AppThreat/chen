package io.appthreat.jimple2cpg.unpacking

import better.files.File
import io.appthreat.jimple2cpg.Jimple2Cpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.util.zip.{ZipEntry, ZipOutputStream}

class ApkBundleUnpackingTests extends AnyWordSpec with Matchers {

    /** Build a minimal apk-like zip containing the given entries. */
    private def writeZip(target: File, entries: Map[String, Array[Byte]]): Unit = {
        val zos = new ZipOutputStream(target.newOutputStream)
        try
            entries.foreach { case (name, data) =>
                zos.putNextEntry(new ZipEntry(name))
                zos.write(data)
                zos.closeEntry()
            }
        finally zos.close()
    }

    "extractApkBundle" should {

        "return only the apks that contain dalvik bytecode" in {
            File.usingTemporaryDirectory("apk-bundle-test") { tmpDir =>
                val baseApk  = tmpDir.createChild("base.apk")
                val splitApk = tmpDir.createChild("split_config.xxhdpi.apk")
                writeZip(baseApk, Map("classes.dex" -> "dex".getBytes, "res/x.png" -> Array.empty))
                writeZip(splitApk, Map("res/y.png" -> Array.empty))
                val bundle = tmpDir.createChild("app.apkm")
                writeZip(
                  bundle,
                  Map(
                    "base.apk"                 -> baseApk.byteArray,
                    "split_config.xxhdpi.apk"  -> splitApk.byteArray,
                    "info.json"                -> "{}".getBytes
                  )
                )

                val extractDir = tmpDir.createChild("out", asDirectory = true)
                val result     = Jimple2Cpg().extractApkBundle(bundle, extractDir)
                result.map(_.name) should contain only "base.apk"
            }
        }

        "fall back to all apks when none could be inspected for dex" in {
            File.usingTemporaryDirectory("apk-bundle-test") { tmpDir =>
                val splitOne = tmpDir.createChild("split_config.en.apk")
                val splitTwo = tmpDir.createChild("split_config.de.apk")
                writeZip(splitOne, Map("res/a.png" -> Array.empty))
                writeZip(splitTwo, Map("res/b.png" -> Array.empty))
                val bundle = tmpDir.createChild("app.apks")
                writeZip(
                  bundle,
                  Map(
                    "split_config.en.apk" -> splitOne.byteArray,
                    "split_config.de.apk" -> splitTwo.byteArray
                  )
                )

                val extractDir = tmpDir.createChild("out", asDirectory = true)
                val result     = Jimple2Cpg().extractApkBundle(bundle, extractDir)
                result.map(_.name).toSet shouldBe Set("split_config.en.apk", "split_config.de.apk")
            }
        }
    }
}
