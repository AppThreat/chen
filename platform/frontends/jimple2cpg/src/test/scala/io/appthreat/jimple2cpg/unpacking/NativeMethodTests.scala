package io.appthreat.jimple2cpg.unpacking

import better.files.File
import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.queryengine.summaries.FlowSummaryComputer
import io.appthreat.jimple2cpg.testfixtures.JimpleCodeToCpgFixture
import io.appthreat.jimple2cpg.util.JImage
import io.appthreat.jimple2cpg.{Config, Jimple2Cpg}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Paths}
import java.util.jar.{JarEntry, JarOutputStream}
import scala.compiletime.uninitialized
import scala.util.Using

/** JNI `native` methods have no bytecode body. Soot reports a dex native method as concrete but
  * keeps no method source for it, so the frontend used to stub it without a BLOCK, and every
  * `method.block` query on the graph - the flow summaries of `atom reachables` first - failed with
  * "next on empty iterator". Every METHOD must have a BLOCK, from dex and from class files alike.
  *
  * `nativemethods/classes.dex` is `src/demo/NativeBridge.java` compiled with `javac --release 8`
  * and `d8 --min-api 21` (build-tools 36.0.0).
  */
class NativeMethodTests extends AnyWordSpec with Matchers with BeforeAndAfterAll:

  private val resources     = Paths.get(getClass.getResource("/nativemethods").toURI)
  private var dexCpg: Cpg   = uninitialized
  private var classCpg: Cpg = uninitialized
  private var workDir: File = uninitialized

  private val nativeMethods = Map(
    "demo.NativeBridge.stringFromJNI:java.lang.String()" -> 0,
    "demo.NativeBridge.checksum:int(byte[],int)"         -> 3, // this, data, length
    "demo.NativeBridge.nativeLog:void(java.lang.String)" -> 1
  )

  override protected def beforeAll(): Unit =
    super.beforeAll()
    workDir = File.newTemporaryDirectory("native-methods")
    // Soot needs an android.jar for dex input. A stub with the running JDK's java.lang classes
    // gives it the basic classes and needs no Android SDK; other platform types stay phantom.
    val androidJar = workDir / "android.jar"
    val jdk        = JImage.open(JImage.imageFile(Paths.get(System.getProperty("java.home")))).get
    Using.resource(new JarOutputStream(androidJar.newOutputStream)) { jar =>
        jdk.entries
            .filter(e => e.startsWith("/java.base/java/lang/") && e.count(_ == '/') == 4)
            .filter(_.endsWith(".class"))
            .foreach { entry =>
              jar.putNextEntry(new JarEntry(entry.stripPrefix("/java.base/")))
              jar.write(jdk.read(entry).get)
              jar.closeEntry()
            }
    }
    dexCpg = build(resources.resolve("classes.dex").toString, Some(androidJar.pathAsString))

    val classes = (workDir / "classes").createDirectory()
    val source  = classes / "NativeBridge.java"
    Files.copy(resources.resolve("src/demo/NativeBridge.java"), source.path)
    JimpleCodeToCpgFixture.compileJava(source.toJava)
    source.delete()
    classCpg = build(classes.pathAsString, None)
  end beforeAll

  override protected def afterAll(): Unit =
    Option(dexCpg).foreach(_.close())
    Option(classCpg).foreach(_.close())
    Option(workDir).foreach(_.delete(swallowIOExceptions = true))
    super.afterAll()

  private def build(input: String, android: Option[String]): Cpg =
    val base = Config().withInputPath(input).withFullResolver(true).withRecurse(true)
        .withOutputPath((workDir / s"${input.hashCode.abs}.atom").pathAsString)
    val config = android.fold(base)(base.withAndroid)
    val cpg    = new Jimple2Cpg().createCpgWithOverlays(config).get
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(cpg))
    cpg

  for (inputName, cpg) <- List(("a dex file", () => dexCpg), ("class files", () => classCpg)) do
    s"the jimple frontend given $inputName" should {
        "give every method exactly one BLOCK" in {
            val methods = cpg().method.l
            methods should not be empty
            methods.filterNot(_.astChildren.isBlock.size == 1).map(_.fullName) shouldBe empty
            cpg().method.internal.fullName.toSet should contain allElementsOf nativeMethods.keySet
        }

        "model native methods as bodyless with their parameters and return" in {
            for (fullName, params) <- nativeMethods do
              withClue(fullName) {
                  val m = cpg().method.fullNameExact(fullName).head
                  m.block.astChildren.size shouldBe 0
                  m.parameter.size shouldBe params
                  m.methodReturn.typeFullName shouldBe fullName.split(':')(1).takeWhile(_ != '(')
              }
        }

        "link the calls to native methods" in {
            (cpg().call.methodFullName.toSet should contain).allOf(
              "demo.NativeBridge.checksum:int(byte[],int)",
              "demo.NativeBridge.nativeLog:void(java.lang.String)",
              "demo.NativeBridge.stringFromJNI:java.lang.String()"
            )
        }

        "compute flow summaries for every method (what atom reachables does)" in {
            val summaries = FlowSummaryComputer.computeAll(cpg())
            summaries.keySet should contain allElementsOf nativeMethods.keySet
            summaries.keySet should contain("demo.NativeBridge.verify:int(java.lang.String)")
            // Nothing is known to flow through a body that does not exist.
            nativeMethods.keys.foreach(n => summaries(n).paramToReturn shouldBe empty)
        }
    }
  end for

  "the dex and class-file graphs" should {
      "describe the native methods the same way" in {
          def shape(cpg: Cpg) = cpg.method.fullNameExact(nativeMethods.keys.toSeq*).map(m =>
              (
                m.fullName,
                m.parameter.size,
                m.astChildren.isBlock.size,
                m.methodReturn.typeFullName
              )
          ).toSet
          shape(dexCpg) shouldBe shape(classCpg)
      }
  }
end NativeMethodTests
