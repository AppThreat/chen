package io.appthreat.jimple2cpg.util

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.io.{ByteArrayOutputStream, DataOutputStream}
import java.net.URI
import java.nio.file.{FileSystems, Files, Path, Paths, StandardCopyOption}
import java.nio.{ByteBuffer, ByteOrder}
import scala.jdk.CollectionConverters.*
import scala.sys.process.*
import scala.util.{Try, Using}

/** The jimage reader must return exactly what the running JVM's jrt:/ file system returns, as Soot
  * reads through jrt:/ on the JVM and through this reader in a native image.
  */
class JImageTests extends AnyWordSpec with Matchers:

  private val javaHome              = Paths.get(System.getProperty("java.home"))
  private val imageFile             = JImage.imageFile(javaHome)
  private lazy val image            = JImage.open(imageFile).get
  private lazy val jrtModules: Path = JdkClassSource.jrtModulesRoot

  private def jrtBytes(module: String, internalName: String): Array[Byte] =
      Files.readAllBytes(jrtModules.resolve(module).resolve(s"$internalName.class"))

  /** Every class file under a jrt:/ module, as (module, internal name). */
  private def jrtClasses(module: String): List[String] =
    val root = jrtModules.resolve(module)
    Using.resource(Files.walk(root)) { stream =>
        stream.iterator().asScala
            .filter(p => p.toString.endsWith(".class") && Files.isRegularFile(p))
            .map(p => root.relativize(p).toString.stripSuffix(".class"))
            .filterNot(_ == "module-info")
            .toList
    }

  private def tempDir(prefix: String): Path =
    val dir = Files.createTempDirectory(prefix)
    dir.toFile.deleteOnExit()
    dir

  "JImage.open" should {
      "open the running JDK's image" in {
          image.classCount should be > 1000
          (image.moduleNames should contain).allOf("java.base", "java.sql", "java.desktop")
      }

      "reject a missing file" in {
          JImage.open(tempDir("jimage-missing").resolve("modules")).isFailure shouldBe true
      }

      "reject a file that is not a jimage" in {
          val file = tempDir("jimage-bad").resolve("modules")
          Files.write(file, "this is not a jimage, just some text long enough".getBytes)
          val err = JImage.open(file).failed.get
          err.getMessage should include("not an image file")
      }

      "reject an empty and a header-only file" in {
          val dir   = tempDir("jimage-short")
          val empty = Files.write(dir.resolve("empty"), Array.emptyByteArray)
          JImage.open(empty).isFailure shouldBe true
          val headerOnly =
              Files.write(dir.resolve("header"), Files.readAllBytes(imageFile).take(28))
          JImage.open(headerOnly).failed.get.getMessage should include("truncated")
      }

      "reject an unsupported image version" in {
          val header = ByteBuffer.wrap(Files.readAllBytes(imageFile).take(4096))
          val order = Seq(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)
              .find(o => header.duplicate().order(o).getInt(0) == 0xcafedada).get
          header.order(order).putInt(4, 2 << 16)
          val file = Files.write(tempDir("jimage-version").resolve("modules"), header.array())
          JImage.open(file).failed.get.getMessage should include("unsupported version 2.0")
      }

      "read an image in the other byte order" in {
          // Only the index is in platform byte order; flip it and the reader must still work.
          val small = jlink("endian").getOrElse(cancel("jlink is not available"))
          val order = ByteOrder.nativeOrder()
          val other =
              if order == ByteOrder.LITTLE_ENDIAN then ByteOrder.BIG_ENDIAN
              else ByteOrder.LITTLE_ENDIAN
          val original = ByteBuffer.wrap(Files.readAllBytes(JImage.imageFile(small))).order(order)
          val ints     = 7 + 2 * original.getInt(16)
          val flipped  = ByteBuffer.wrap(original.array().clone())
          for i <- 0 until ints do flipped.order(other).putInt(i * 4, original.getInt(i * 4))
          val file    = Files.write(tempDir("jimage-endian").resolve("modules"), flipped.array())
          val swapped = JImage.open(file).get
          swapped.readClass("java/lang/Object").get shouldBe jrtBytes(
            "java.base",
            "java/lang/Object"
          )
          swapped.classCount shouldBe JImage.open(JImage.imageFile(small)).get.classCount
      }
  }

  "JImage.readClass" should {
      "return the same bytes as jrt:/ for classes Soot loads first" in {
          val classes = List(
            "java.base"     -> "java/lang/Object",
            "java.base"     -> "java/lang/String",
            "java.base"     -> "java/lang/invoke/StringConcatFactory",
            "java.base"     -> "java/lang/invoke/LambdaMetafactory",
            "java.base"     -> "java/security/MessageDigest",
            "java.base"     -> "java/util/Map$Entry",
            "java.base"     -> "javax/crypto/Cipher",
            "java.sql"      -> "java/sql/Connection",
            "java.net.http" -> "java/net/http/HttpClient"
          )
          for (module, name) <- classes do
            withClue(name) { image.readClass(name).get shouldBe jrtBytes(module, name) }
      }

      "return the same bytes as jrt:/ for every class in java.base" in {
          val classes = jrtClasses("java.base")
          classes.size should be > 5000
          val mismatches = classes.filterNot(name =>
              image.readClass(name).exists(_.sameElements(jrtBytes("java.base", name)))
          )
          mismatches shouldBe empty
      }

      "find every class of every module that jrt:/ lists" in {
          val modules = Using.resource(Files.list(jrtModules))(_.iterator().asScala.toList)
              .map(_.getFileName.toString)
          image.moduleNames shouldBe modules.toSet
          val missing = modules.flatMap(m => jrtClasses(m).filterNot(image.containsClass))
          missing shouldBe empty
      }

      "return None for classes that are not in the image" in {
          image.readClass("java/lang/DoesNotExist") shouldBe None
          image.readClass("com/example/Missing") shouldBe None
          image.readClass("Object") shouldBe None
          image.readClass("") shouldBe None
          image.containsClass("java/lang") shouldBe false
      }

      "list resources by full name and read them back" in {
          val sample = image.entries.filter(_.endsWith(".class")).take(500).toList
          sample should not be empty
          sample.foreach(name => withClue(name) { image.read(name) should not be empty })
          image.read("/java.base/java/lang/Object.class").get shouldBe jrtBytes(
            "java.base",
            "java/lang/Object"
          )
          image.read("/java.sql/java/lang/Object.class") shouldBe None
      }

      "serve concurrent readers" in {
          val names   = jrtClasses("java.base").take(2000)
          val results = parallelMap(names, 8)(n => image.readClass(n).map(_.length).getOrElse(-1))
          results.count(_ < 0) shouldBe 0
      }
  }

  "JImage.open" when {
      "the image is compressed with jlink's zip plugin" should {
          "inflate the class bytes" in {
              val zipped = jlink("zip", "--compress=zip-6").getOrElse(
                cancel("jlink --compress=zip-6 is not available")
              )
              val compressed = JImage.open(JImage.imageFile(zipped)).get
              compressed.compressedEntries should be > 0
              for name <- List("java/lang/Object", "java/lang/String", "java/util/HashMap") do
                withClue(name) {
                    compressed.readClass(name).get shouldBe jrtBytes("java.base", name)
                }
          }
      }

      "the image uses a compression plugin the reader does not support" should {
          "report those classes as unreadable instead of returning corrupt bytes" in {
              // --compress=1 is jlink's (deprecated) constant-string sharing, `compact-cp`.
              val shared = jlink("compact-cp", "--compress=1").getOrElse(
                cancel("jlink --compress=1 is not available")
              )
              val img = JImage.open(JImage.imageFile(shared)).get
              if img.compressedEntries == 0 then cancel("jlink did not compress any resource")
              val names   = List("java/lang/Object", "java/lang/String", "java/util/HashMap")
              val results = names.map(n => n -> img.readClass(n))
              results.foreach { case (n, bytes) =>
                  bytes.foreach(b => withClue(n) { b shouldBe jrtBytes("java.base", n) })
              }
          }
      }
  }

  "JImage.nameHash" should {
      "hash the modified UTF-8 bytes of a name, as ImageStringsReader does" in {
          val seed = 0x01000193
          def reference(s: String): Int =
            val out = new ByteArrayOutputStream()
            new DataOutputStream(out).writeUTF(s) // modified UTF-8 with a 2-byte length prefix
            out.toByteArray.drop(2).foldLeft(seed)((h, b) => (h * seed) ^ (b & 0xff)) & 0x7fffffff
          for s <- List(
              "/java.base/java/lang/Object.class",
              "caf\u00e9",
              "\u65e5\u672c",
              "a\u0000b",
              "\ud83d\ude00",
              ""
            )
          do withClue(s) { JImage.nameHash(s, seed) shouldBe reference(s) }
      }
  }

  "JImage.decodeModifiedUtf8" should {
      "decode what DataOutputStream.writeUTF encodes" in {
          for s <- List(
              "java/lang/Object",
              "caf\u00e9",
              "\u65e5\u672c\u8a9e",
              "a\u0000b",
              "\ud83d\ude00"
            )
          do
            val out = new ByteArrayOutputStream()
            new DataOutputStream(out).writeUTF(s)
            JImage.decodeModifiedUtf8(out.toByteArray.drop(2)) shouldBe s
      }
  }

  /** Link java.base into a new runtime image with the given jlink options. */
  private def jlink(name: String, options: String*): Option[Path] =
    val jlinkExe = javaHome.resolve("bin").resolve(
      if System.getProperty("os.name").toLowerCase.contains("win") then "jlink.exe" else "jlink"
    )
    if !Files.isExecutable(jlinkExe) then None
    else
      val output = tempDir(s"jimage-$name").resolve("image")
      val cmd = Seq(
        jlinkExe.toString,
        "--add-modules",
        "java.base",
        "--output",
        output.toString
      ) ++ options
      val log    = new StringBuilder
      val status = Try(Process(cmd).!(ProcessLogger(l => log.append(l).append('\n')))).getOrElse(-1)
      if status == 0 && Files.isRegularFile(JImage.imageFile(output)) then Some(output) else None

  private def parallelMap[A, B](items: List[A], threads: Int)(f: A => B): List[B] =
    val pool = java.util.concurrent.Executors.newFixedThreadPool(threads)
    try items.map(a => pool.submit(() => f(a))).map(_.get())
    finally pool.shutdown()
end JImageTests
