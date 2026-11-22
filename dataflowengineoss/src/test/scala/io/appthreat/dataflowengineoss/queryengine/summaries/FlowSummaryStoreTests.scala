package io.appthreat.dataflowengineoss.queryengine.summaries

import io.appthreat.x2cpg.passes.frontend.CacheControl
import org.scalatest.BeforeAndAfterEach
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{FileSystemException, Files, LinkOption, Path}
import scala.jdk.CollectionConverters.*

/** The summary store writes beside the user-named slices file, and its entry names are fingerprint
  * hashes a checkout beside that file can predict. A symbolic link at an entry's name must not
  * decide where the summary JSON goes, and a linked entry must never be read.
  */
class FlowSummaryStoreTests extends AnyWordSpec with Matchers with BeforeAndAfterEach:

  override def beforeEach(): Unit = CacheControl.enable(CacheControl.Summary)
  override def afterEach(): Unit = CacheControl.enable(CacheControl.Summary)

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

  private val summaries = Map(
    "foo" -> MethodFlowSummary("foo", Set(0), Map.empty, returnFromInternal = false, Set.empty)
  )

  private def entry(cacheDir: Path, fingerprint: String): Path =
      cacheDir.resolve(s"flowsummary-$fingerprint.json")

  "FlowSummaryStore" should {

      "replace a symbolic link at the entry's name instead of writing through it" in {
          val cacheDir = Files.createTempDirectory("flowsummary-link")
          val outside  = Files.createTempDirectory("flowsummary-target")
          val victim   = outside.resolve("victim.json")
          Files.writeString(victim, "PRECIOUS")
          symlink(entry(cacheDir, "fp-1"), victim)

          new FlowSummaryStore(cacheDir.toString).store("fp-1", summaries)

          Files.readString(victim) shouldBe "PRECIOUS"
          Files.isRegularFile(entry(cacheDir, "fp-1"), LinkOption.NOFOLLOW_LINKS) shouldBe true
          val stream = Files.list(cacheDir)
          try stream.iterator().asScala
              .filter(_.getFileName.toString.endsWith(".tmp"))
              .toList shouldBe empty
          finally stream.close()
      }

      "leave a dangling link's target path uncreated" in {
          val cacheDir = Files.createTempDirectory("flowsummary-dangling")
          val nowhere  = cacheDir.resolve("nowhere").resolve("gone.json")
          symlink(entry(cacheDir, "fp-1"), nowhere)

          new FlowSummaryStore(cacheDir.toString).store("fp-1", summaries)

          Files.exists(nowhere) shouldBe false
          Files.isRegularFile(entry(cacheDir, "fp-1"), LinkOption.NOFOLLOW_LINKS) shouldBe true
      }

      "treat an entry that is a symbolic link as a miss" in {
          val cacheDir = Files.createTempDirectory("flowsummary-miss")
          val outside  = Files.createTempDirectory("flowsummary-miss-target")
          val secret   = outside.resolve("secret.json")
          Files.writeString(secret, "[]")
          symlink(entry(cacheDir, "fp-1"), secret)

          new FlowSummaryStore(cacheDir.toString).restore("fp-1") shouldBe None
          Files.readString(secret) shouldBe "[]"
      }

      "store and restore a summary set over a plain directory" in {
          val cacheDir = Files.createTempDirectory("flowsummary-plain")
          val store    = new FlowSummaryStore(cacheDir.toString)

          store.restore("fp-1") shouldBe None
          store.store("fp-1", summaries)
          store.restore("fp-1") shouldBe Some(summaries)
      }

      "neither store nor restore while the summary cache is disabled" in {
          val cacheDir = Files.createTempDirectory("flowsummary-disabled")
          CacheControl.disable(CacheControl.Summary)
          val store = new FlowSummaryStore(cacheDir.toString)
          store.store("fp-1", summaries)
          store.restore("fp-1") shouldBe None
          Files.exists(entry(cacheDir, "fp-1")) shouldBe false
      }
  }
end FlowSummaryStoreTests
