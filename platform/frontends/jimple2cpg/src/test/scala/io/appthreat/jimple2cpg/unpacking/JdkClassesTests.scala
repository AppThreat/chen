package io.appthreat.jimple2cpg.unpacking

import io.appthreat.jimple2cpg.testfixtures.JimpleCodeToCpgFixture
import io.appthreat.jimple2cpg.util.JdkClasses
import io.appthreat.jimple2cpg.{Config, Jimple2Cpg}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Path, Paths}
import java.util.jar.{JarEntry, JarOutputStream}
import scala.compiletime.uninitialized
import scala.jdk.CollectionConverters.*
import scala.util.Using

/** A GraalVM native image cannot read JDK classes through jrt:/, so it reads them from an installed
  * JDK's lib/modules (`image` mode). The graph must not depend on which of the two served the JDK
  * classes. Without any JDK (`none` mode) the frontend must still succeed.
  */
class JdkClassesTests extends AnyWordSpec with Matchers with BeforeAndAfterAll:

  private var classesDir: Path = uninitialized
  private var jarFile: Path    = uninitialized

  override protected def beforeAll(): Unit =
    super.beforeAll()
    val src = Paths.get(getClass.getResource("/jdkclasses").toURI)
    classesDir = Files.createTempDirectory("jdkclasses-classes")
    compile(src, classesDir)
    jarFile = Files.createTempDirectory("jdkclasses-jar").resolve("demo.jar")
    jar(classesDir, jarFile)

  private def compile(src: Path, out: Path): Unit =
    val javac   = JimpleCodeToCpgFixture.getJavaCompiler
    val manager = javac.getStandardFileManager(null, null, null)
    val sources = Using.resource(Files.walk(src))(
      _.iterator().asScala.filter(_.toString.endsWith(".java")).map(_.toFile).toList
    )
    val ok = javac.getTask(
      null,
      manager,
      null,
      List("-g", "--release", "17", "-d", out.toString).asJava,
      null,
      manager.getJavaFileObjectsFromFiles(sources.asJava)
    ).call()
    assert(ok, "the jdkclasses fixture failed to compile")

  private def jar(dir: Path, target: Path): Unit =
      Using.resource(new JarOutputStream(Files.newOutputStream(target))) { out =>
          Using.resource(Files.walk(dir)) { files =>
              files.iterator().asScala.filter(Files.isRegularFile(_)).foreach { f =>
                out.putNextEntry(new JarEntry(dir.relativize(f).toString.replace('\\', '/')))
                Files.copy(f, out)
                out.closeEntry()
              }
          }
      }

  private def withMode[T](mode: String)(f: => T): T =
    val previous = Option(System.getProperty(JdkClasses.ModeProperty))
    System.setProperty(JdkClasses.ModeProperty, mode)
    try f
    finally
        previous match
          case Some(value) => System.setProperty(JdkClasses.ModeProperty, value)
          case None        => System.clearProperty(JdkClasses.ModeProperty)

  private def build(mode: String, input: Path, fullResolver: Boolean): Cpg = withMode(mode) {
      val config = Config()
          .withInputPath(input.toString)
          .withOutputPath(Files.createTempFile("jdkclasses", ".atom").toString)
          .withFullResolver(fullResolver)
          .withRecurse(true)
      new Jimple2Cpg().createCpg(config).get
  }

  /** The parts of the graph that JDK classes feed into. */
  private def fingerprint(cpg: Cpg): Map[String, Set[String]] = Map(
    "typeDecls" -> cpg.typeDecl.map(t =>
        s"${t.fullName} external=${t.isExternal} inherits=${t.inheritsFromTypeFullName.sorted.mkString(",")}"
    ).toSet,
    "methods" -> cpg.method.map(m => s"${m.fullName} external=${m.isExternal}").toSet,
    "calls" -> cpg.call.map(c =>
        s"${c.method.fullName} -> ${c.methodFullName} ${c.dispatchType} ${c.signature}"
    ).toSet,
    "types"  -> cpg.typ.fullName.toSet,
    "locals" -> cpg.local.map(l => s"${l.method.fullName.head}:${l.name}:${l.typeFullName}").toSet
  )

  private def assertSameGraph(platform: Cpg, image: Cpg): Unit =
    val expected = fingerprint(platform)
    val actual   = fingerprint(image)
    for key <- expected.keys do
      withClue(s"$key only with jrt:/ ${(expected(key) -- actual(key)).take(10)}; " +
          s"only with the image ${(actual(key) -- expected(key)).take(10)}: ") {
          actual(key) shouldBe expected(key)
      }

  "the jimple frontend" when {
      for (inputName, fullResolver) <- List(
          ("a class directory", false),
          ("a class directory", true),
          ("a jar", false),
          ("a jar", true)
        )
      do
        s"given $inputName${if fullResolver then " with the full resolver" else ""}" should {
            "build the same graph from the JDK image as from jrt:/" in {
                val input    = if inputName == "a jar" then jarFile else classesDir
                val platform = build("platform", input, fullResolver)
                val image    = build("image", input, fullResolver)
                try assertSameGraph(platform, image)
                finally
                  platform.close()
                  image.close()
            }
        }

      "reading JDK classes from the image" should {
          "resolve JDK supertypes, calls and other-module types" in {
              val cpg = build("image", classesDir, fullResolver = true)
              try
                cpg.typeDecl.fullNameExact("demo.Registry").inheritsFromTypeFullName.l should contain(
                  "java.util.AbstractMap"
                )
                cpg.typeDecl.fullNameExact("demo.Shapes$Circle").inheritsFromTypeFullName.l should contain(
                  "java.lang.Record"
                )
                cpg.typeDecl.fullNameExact("demo.Registry$RegistryException")
                    .inheritsFromTypeFullName.l should contain("java.io.IOException")
                (cpg.call.methodFullName.toSet should contain).allOf(
                  "java.security.MessageDigest.getInstance:java.security.MessageDigest(java.lang.String)",
                  "java.sql.DriverManager.getConnection:java.sql.Connection(java.lang.String)",
                  "java.net.http.HttpClient.newHttpClient:java.net.http.HttpClient()"
                )
              finally cpg.close()
          }
      }

      "no JDK is available" should {
          "still build the graph of the application classes" in {
              val cpg = build("none", jarFile, fullResolver = true)
              try
                (cpg.method.isExternal(false).fullName.toSet should contain).allOf(
                  "demo.Hasher.digest:byte[](java.lang.String)",
                  "demo.Registry.close:void()",
                  "demo.Shapes.area:double(demo.Shapes$Shape)",
                  "demo.Store.lookup:java.lang.String(java.lang.String,java.lang.String)"
                )
                cpg.call.methodFullName.toSet should contain(
                  "java.security.MessageDigest.getInstance:java.security.MessageDigest(java.lang.String)"
                )
              finally cpg.close()
          }
      }
  }
end JdkClassesTests
