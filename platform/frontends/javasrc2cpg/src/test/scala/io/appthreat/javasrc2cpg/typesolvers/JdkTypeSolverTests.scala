package io.appthreat.javasrc2cpg.typesolvers

import com.github.javaparser.symbolsolver.javassistmodel.JavassistClassDeclaration
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver
import io.appthreat.javasrc2cpg.Config
import io.appthreat.javasrc2cpg.passes.AstCreationPass
import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.javasrc2cpg.typesolvers.noncaching.JdkJarTypeSolver
import io.appthreat.x2cpg.utils.JImage
import io.shiftleft.semanticcpg.language.*

import java.nio.file.{Files, Path, Paths}
import java.util.zip.{ZipEntry, ZipOutputStream}
import scala.jdk.CollectionConverters.*
import scala.util.{Try, Using}

/** The JDK types of the analysed code come from a JDK's own classes, which a native image can read,
  * and not from reflection, which in a native image finds a JDK class but none of its members.
  */
class JdkTypeSolverTests extends JavaSrcCode2CpgFixture:

  private val realHome  = Paths.get(System.getProperty("java.home"))
  private val realImage = JImage.imageFile(realHome)

  /** A JDK home with a `lib/modules` image and no jmods, as JDKs built under JEP 493 ship. */
  private lazy val jmodlessHome: Path =
    val home = Files.createTempDirectory("jmodless-jdk")
    home.toFile.deleteOnExit()
    val image = JImage.imageFile(home)
    Files.createDirectories(image.getParent)
    Try(Files.createSymbolicLink(image, realImage)).orElse(Try(Files.copy(realImage, image))).get
    home

  private def solverFor(home: Path): (SimpleCombinedTypeSolver, JdkJarTypeSolver) =
    val combined = new SimpleCombinedTypeSolver()
    val jdk      = JdkJarTypeSolver.fromJdkPath(home.toString)
    combined.addNonCachingTypeSolver(jdk)
    (combined, jdk)

  "the JDK type solver" should {

      "resolve JDK types and their members from a JDK without jmods" in {
          val (combined, jdk) = solverFor(jmodlessHome)
          jdk.knownPackagePrefixes should contain("java.io")
          val ref = combined.tryToSolveType("java.io.ObjectInputStream")
          ref.isSolved shouldBe true
          val declaration = ref.getCorrespondingDeclaration
          declaration shouldBe a[JavassistClassDeclaration]
          declaration.getDeclaredMethods.asScala.map(_.getName) should contain("readObject")
          combined.tryToSolveType("java.util.Map.Entry").isSolved shouldBe true
          combined.tryToSolveType("java.io.NoSuchType").isSolved shouldBe false
      }

      "find classes in the image with a file: URL, which a native image can create" in {
          val image     = JImage.openShared(realImage).get
          val classPath = new JImageClassPath(image)
          classPath.find("java.lang.Object").getProtocol shouldBe "file"
          classPath.find("java.util.Map$Entry") should not be null
          classPath.find("java.lang.NoSuchType") shouldBe null
          Using.resource(classPath.openClassfile("java.lang.Object")) { in =>
              in.readNBytes(4).toSeq shouldBe Seq(0xca, 0xfe, 0xba, 0xbe).map(_.toByte)
          }
      }

      "find classes in a jmod with a file: URL, as jmod: URLs have no handler in a native image" in {
          val dir  = Files.createTempDirectory("jmod-classpath")
          val jmod = dir.resolve("demo.jmod")
          val bytes =
              JImage.openShared(realImage).get.readClass("java/lang/Object").get
          Using.resource(ZipOutputStream(Files.newOutputStream(jmod))) { zip =>
            zip.putNextEntry(ZipEntry("classes/demo/A.class"))
            zip.write(bytes)
            zip.closeEntry()
          }
          val classPath = new JmodClassPath(jmod.toString)
          classPath.find("demo.A").getProtocol shouldBe "file"
          classPath.find("demo.B") shouldBe null
      }
  }

  "the JDK solvers" should {
      val withClasses = JdkJarTypeSolver.fromJdkPath(realHome.toString)
      val empty       = new JdkJarTypeSolver()

      "ask the JDK's classes before reflection on the JVM" in {
          val solvers = AstCreationPass.jdkSolvers(Some(withClasses), inNativeImage = false)
          solvers.head shouldBe withClasses
          solvers.last shouldBe a[ReflectionTypeSolver]
      }

      "leave reflection out of a native image that has the JDK's classes" in {
          AstCreationPass.jdkSolvers(Some(withClasses), inNativeImage = true) shouldBe List(
            withClasses
          )
      }

      "fall back to reflection in a native image without JDK classes" in {
          AstCreationPass.jdkSolvers(None, inNativeImage = true).map(_.getClass) shouldBe List(
            classOf[ReflectionTypeSolver]
          )
          AstCreationPass.jdkSolvers(Some(empty), inNativeImage = true).last shouldBe a[
            ReflectionTypeSolver
          ]
      }
  }

  "a call through a JDK type" should {
      val cpg = code("""
          |import java.io.InputStream;
          |import java.io.ObjectInputStream;
          |
          |public class Reader {
          |    public Object read(InputStream s) throws Exception {
          |        ObjectInputStream in = new ObjectInputStream(s);
          |        return in.readObject();
          |    }
          |}
          |""".stripMargin).withConfig(Config().withJdkPath(jmodlessHome.toString))

      "resolve from a JDK without jmods" in {
          cpg.call.name("readObject").methodFullName.l shouldBe List(
            "java.io.ObjectInputStream.readObject:java.lang.Object()"
          )
          cpg.call.name("readObject").code.l shouldBe List("in.readObject()")
      }
  }
end JdkTypeSolverTests
