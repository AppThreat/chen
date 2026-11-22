package io.appthreat.x2cpg.passes.frontend

import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{NewBlock, NewLiteral, NewMethod}
import org.scalatest.BeforeAndAfterEach
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import overflowdb.BatchedUpdate
import overflowdb.BatchedUpdate.DiffGraphBuilder
import overflowdb.util.DiffTool

import java.nio.file.{FileSystemException, Files, LinkOption, Path}
import scala.jdk.CollectionConverters.*

/** The AST cache holds entries under the analysed input, whose own checkout decides what exists
  * there before the run does. A committed symbolic link at an entry's name must not decide where a
  * cache entry is written, a link at the cache directory's position must switch the cache off, and
  * a link at an entry must never be read.
  */
class AstCacheStoreTests extends AnyWordSpec with Matchers with BeforeAndAfterEach:

  override def afterEach(): Unit = CacheControl.enable(CacheControl.Ast)

  /** Creates a symbolic link at `link` pointing at `target`, skipping the test where the platform
    * refuses to create one.
    */
  private def symlink(link: Path, target: Path): Unit =
      try Files.createSymbolicLink(link, target)
      catch
        case e: UnsupportedOperationException =>
            assume(false, s"this platform cannot create symbolic links: ${e.getMessage}")
        case e: FileSystemException =>
            assume(false, s"this platform refused to create a symbolic link: ${e.getMessage}")

  private def buildUnit(body: String): DiffGraphBuilder =
    val diff  = new DiffGraphBuilder
    val m     = NewMethod().name("foo").fullName("foo").lineNumber(7).order(1)
    val block = NewBlock().typeFullName("ANY").order(1)
    val lit   = NewLiteral().code(body).lineNumber(99).order(1)
    diff.addNode(m); diff.addNode(block); diff.addNode(lit)
    diff.addEdge(m, block, EdgeTypes.AST)
    diff.addEdge(block, lit, EdgeTypes.AST)
    diff

  private val cacheKey = CacheKey("file1", "content-v1".getBytes("UTF-8"))

  private def parsed(body: String): Option[ParsedUnit] = Some(ParsedUnit(buildUnit(body)))

  /** The hash of `key` as spelled on disk, from the entry a first run wrote. */
  private def entryStem(cacheDir: Path, suffix: String): String =
      val stream = Files.list(cacheDir)
      val names  = try stream.iterator().asScala.map(_.getFileName.toString).toList
      finally stream.close()
      names
          .flatMap(n => if n.endsWith(suffix) then Some(n.stripSuffix(suffix)) else None)
          .headOption
          .getOrElse(fail(s"no $suffix entry was written"))

  /** Runs one part so the entry exists, then moves it aside and puts `linkTarget` at its name. */
  private def replaceEntryWithLink(cacheDir: Path, suffix: String, linkTarget: Path): Path =
      val store = new AstCacheStore(true, cacheDir.toString, onlyAstCache = false)
      val cold  = new DiffGraphBuilder
      store.process(cold, "file1", Some(cacheKey), "", _ => (), parsed("1"))
      val entry = cacheDir.resolve(entryStem(cacheDir, suffix) + suffix)
      Files.delete(entry)
      symlink(entry, linkTarget)
      entry

  "AstCacheStore in classic mode" should {

      "replace a symbolic link at the entry's name instead of writing through it" in {
          val cache   = Files.createTempDirectory("ast-store-cache")
          val outside = Files.createTempDirectory("ast-store-outside")
          val victim  = outside.resolve("victim.txt")
          Files.writeString(victim, "PRECIOUS")
          replaceEntryWithLink(cache, ".ast", victim)

          val store = new AstCacheStore(true, cache.toString, onlyAstCache = false)
          val warm  = new DiffGraphBuilder
          store.process(warm, "file1", Some(cacheKey), "", _ => (), parsed("2"))

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.isRegularFile(cache.resolve(entryStem(cache, ".ast") + ".ast"), LinkOption.NOFOLLOW_LINKS) shouldBe
              true
      }

      "not create the target of a dangling link at the entry's name" in {
          val cache   = Files.createTempDirectory("ast-store-dangling")
          val nowhere = cache.resolve("nowhere").resolve("gone.txt")
          replaceEntryWithLink(cache, ".ast", nowhere)

          val store = new AstCacheStore(true, cache.toString, onlyAstCache = false)
          val warm  = new DiffGraphBuilder
          store.process(warm, "file1", Some(cacheKey), "", _ => (), parsed("2"))

          Files.exists(nowhere) shouldBe false
          Files.isRegularFile(cache.resolve(entryStem(cache, ".ast") + ".ast"), LinkOption.NOFOLLOW_LINKS) shouldBe
              true
      }

      "treat an entry that is a symbolic link as a miss and reparse the part" in {
          val cache   = Files.createTempDirectory("ast-store-link-miss")
          val outside = Files.createTempDirectory("ast-store-link-target")
          val secret  = outside.resolve("secret.ast")
          Files.write(secret, Array.emptyByteArray)
          replaceEntryWithLink(cache, ".ast", secret)

          var parses = 0
          val store  = new AstCacheStore(true, cache.toString, onlyAstCache = false)
          val warm   = new DiffGraphBuilder
          val produced = store.process(
            warm,
            "file1",
            Some(cacheKey),
            "",
            _ => (),
            { parses += 1; parsed("2") }
          )

          produced shouldBe true
          parses shouldBe 1 // the linked entry was not read; the part was parsed again
          Files.readAllBytes(secret).length shouldBe 0
      }

      "never open the old predictable temporary name, a link there included" in {
          val cache   = Files.createTempDirectory("ast-store-oldtmp")
          val outside = Files.createTempDirectory("ast-store-oldtmp-target")
          val victim  = outside.resolve("victim.txt")
          Files.writeString(victim, "PRECIOUS")
          val store = new AstCacheStore(true, cache.toString, onlyAstCache = false)
          val cold  = new DiffGraphBuilder
          store.process(cold, "file1", Some(cacheKey), "", _ => (), parsed("1"))
          // the temporary name earlier chen versions wrote at, committed as a link: a write to
          // it would truncate the victim
          val oldTmp = cache.resolve(entryStem(cache, ".ast") + ".ast.tmp")
          symlink(oldTmp, victim)
          Files.delete(cache.resolve(entryStem(cache, ".ast") + ".ast"))

          val warm = new DiffGraphBuilder
          store.process(warm, "file1", Some(cacheKey), "", _ => (), parsed("2"))

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.isSymbolicLink(oldTmp) shouldBe true // the name was never opened
          Files.isRegularFile(cache.resolve(entryStem(cache, ".ast") + ".ast"), LinkOption.NOFOLLOW_LINKS) shouldBe
              true
      }
  }

  "AstCacheStore in fragment mode" should {

      "replace a symbolic link at the fragment entry's name instead of writing through it" in {
          val cache   = Files.createTempDirectory("ast-frag-link")
          val outside = Files.createTempDirectory("ast-frag-target")
          val victim  = outside.resolve("victim.frag")
          Files.write(victim, Array.emptyByteArray)

          val store = new AstCacheStore(
            true,
            cache.toString,
            onlyAstCache = false,
            useFragmentCache = true
          )
          val cold = new DiffGraphBuilder
          store.process(cold, "file1", Some(cacheKey), "", _ => (), parsed("1"))
          val entry = cache.resolve(entryStem(cache, ".frag") + ".frag")
          Files.delete(entry)
          symlink(entry, victim)

          val warm = new DiffGraphBuilder
          store.process(warm, "file1", Some(cacheKey), "", _ => (), parsed("2"))

          Files.readAllBytes(victim).length shouldBe 0
          Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS) shouldBe true
      }

      "never open the old predictable fragment temporary name, a link there included" in {
          val cache   = Files.createTempDirectory("ast-frag-oldtmp")
          val outside = Files.createTempDirectory("ast-frag-oldtmp-target")
          val victim  = outside.resolve("victim.txt")
          Files.writeString(victim, "PRECIOUS")
          val store =
              new AstCacheStore(
                true,
                cache.toString,
                onlyAstCache = false,
                useFragmentCache = true
              )
          val cold = new DiffGraphBuilder
          store.process(cold, "file1", Some(cacheKey), "", _ => (), parsed("1"))
          val oldTmp = cache.resolve(entryStem(cache, ".frag") + ".frag.tmp")
          symlink(oldTmp, victim)
          Files.delete(cache.resolve(entryStem(cache, ".frag") + ".frag"))

          val warm = new DiffGraphBuilder
          store.process(warm, "file1", Some(cacheKey), "", _ => (), parsed("2"))

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.isSymbolicLink(oldTmp) shouldBe true // the name was never opened
          Files.isRegularFile(cache.resolve(entryStem(cache, ".frag") + ".frag"), LinkOption.NOFOLLOW_LINKS) shouldBe
              true
      }
  }

  "an AstCacheStore whose cache directory position is a link" should {

      "be unusable, leave the link's target free of cache entries, and still parse every part" in {
          val input   = Files.createTempDirectory("ast-store-input")
          val outside = Files.createTempDirectory("ast-store-chen-target")
          val chen    = input.resolve(".chen")
          symlink(chen, outside)

          val store = new AstCacheStore(true, chen.toString, onlyAstCache = false)
          store.isUsable shouldBe false

          var parses = 0
          val diff   = new DiffGraphBuilder
          val produced = store.process(
            diff,
            "file1",
            Some(cacheKey),
            "",
            _ => (),
            { parses += 1; parsed("1") }
          )

          produced shouldBe true
          parses shouldBe 1
          val stream = Files.list(outside)
          try stream.iterator().asScala.toList shouldBe empty
          finally stream.close()
      }

      "be unusable when anchored at an input whose `.chen` link already holds entries" in {
          val input   = Files.createTempDirectory("ast-store-anchored")
          val outside = Files.createTempDirectory("ast-store-anchored-target")
          // an earlier run through the link left real entries in the target, so the directory
          // `<input>/.chen` exists (through the link) and the deepest-existing walk alone starts
          // below the link
          Files.writeString(outside.resolve("deadbeef.ast"), "STALE")
          val chen = input.resolve(".chen")
          symlink(chen, outside)

          val store =
              new AstCacheStore(
                true,
                chen.toString,
                onlyAstCache = false,
                cacheDirAnchor = Some(input.toString)
              )
          store.isUsable shouldBe false

          val diff = new DiffGraphBuilder
          store.process(diff, "file1", Some(cacheKey), "", _ => (), parsed("1"))
          Files.readString(outside.resolve("deadbeef.ast")) shouldBe "STALE"
          val stream = Files.list(outside)
          try stream.iterator().asScala.map(_.getFileName.toString).toList shouldBe
              List("deadbeef.ast")
          finally stream.close()
      }

      "still be used when the user configured that directory explicitly" in {
          val input   = Files.createTempDirectory("ast-store-trusted")
          val outside = Files.createTempDirectory("ast-store-trusted-target")
          val chen    = input.resolve("my-cache")
          symlink(chen, outside)

          val store =
              new AstCacheStore(true, chen.toString, onlyAstCache = false, trustedCacheDir = true)
          store.isUsable shouldBe true

          val cold = new DiffGraphBuilder
          store.process(cold, "file1", Some(cacheKey), "", _ => (), parsed("1"))

          // the user named this position, so entries land where it points
          val stream = Files.list(outside)
          val names  = try stream.iterator().asScala.map(_.getFileName.toString).toList
          finally stream.close()
          names.count(_.endsWith(".ast")) shouldBe 1
      }
  }

  "a store over a plain cache directory" should {

      "produce the same graph with and without caching, and restore on a warm run" in {
          val cache = Files.createTempDirectory("ast-store-equality")

          val uncached = new DiffGraphBuilder
          new AstCacheStore(false, cache.toString, onlyAstCache = false)
              .process(uncached, "file1", Some(cacheKey), "", _ => (), parsed("42"))

          val cached = new AstCacheStore(true, cache.toString, onlyAstCache = false)
          val cold   = new DiffGraphBuilder
          cached.process(cold, "file1", Some(cacheKey), "", _ => (), parsed("42"))

          var warmParses = 0
          val warm       = new DiffGraphBuilder
          cached.process(
            warm,
            "file1",
            Some(cacheKey),
            "",
            _ => (),
            { warmParses += 1; parsed("42") }
          )
          warmParses shouldBe 0

          def materialize(diff: DiffGraphBuilder): Cpg =
              val g = Cpg.emptyCpg
              BatchedUpdate.applyDiff(g.graph, diff)
              g

          val gUncached = materialize(uncached)
          val gCold     = materialize(cold)
          val gWarm     = materialize(warm)
          try
            DiffTool.compare(gUncached.graph, gCold.graph).asScala.toList shouldBe empty
            DiffTool.compare(gCold.graph, gWarm.graph).asScala.toList shouldBe empty
          finally
            gUncached.close(); gCold.close(); gWarm.close()
      }
  }
end AstCacheStoreTests
