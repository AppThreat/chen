package io.appthreat.c2cpg.passes

import better.files.File
import io.appthreat.x2cpg.passes.taggers.MemApiVocab
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.io.{ByteArrayOutputStream, PrintStream}

/** The memory-api config example the documentation carries, at `docs/v4/api.md` in the repository
  * root: the JSON block the page shows decodes exactly as the surrounding prose states, with the
  * declared roles present at the indices the page names, and a malformed variant of the same
  * document is dropped entry by entry rather than accepted silently. Reading the example out of the
  * page keeps it from drifting from what the vocabulary accepts.
  */
class MemApiVocabDocsExampleTests extends AnyWordSpec with Matchers:

  /** Captures what a decoding failure prints, so a dropped entry has to SAY it was dropped. */
  private def withCapturedErr[A](body: => A): (A, String) =
    val original = System.err
    val captured = new ByteArrayOutputStream()
    System.setErr(new PrintStream(captured, true, "UTF-8"))
    try (body, captured.toString("UTF-8"))
    finally System.setErr(original)

  /** The documentation page, found above the working directory the test runs in (the c2cpg
    * directory inside the repository).
    */
  private def docsPage: String =
    val root = Iterator
        .iterate(File(System.getProperty("user.dir")))(_.parentOption.orNull)
        .takeWhile(_ != null)
        .take(12)
        .find(dir => (dir / "docs" / "v4" / "api.md").exists)
        .getOrElse(fail("docs/v4/api.md not found above the working directory"))
    (root / "docs" / "v4" / "api.md").contentAsString

  /** The fenced JSON block of the page that declares the example's pool profile. */
  private def docsExampleConfig: String =
    val fences = "(?s)```json\n(.*?)```".r.findAllMatchIn(docsPage).map(_.group(1)).toList
    fences.find(_.contains("acct_pool_new")).getOrElse(
      fail("the documentation page carries no memory-api config example to load")
    )

  "the documented memory-api config example" should {

      "decode alongside the built-in inventory, whose entries it does not name" in {
          val inventory = MemApiVocab.inventory(Some(docsExampleConfig))
          inventory("acct_new").alloc shouldBe Some("acctmem")
          inventory("acct_new").len shouldBe Some(1)
          inventory("acct_new").nullableReturn shouldBe true
          inventory("acct_del").free shouldBe Some("acctmem")
          inventory("malloc").alloc shouldBe Some("heap")
          inventory("free").free shouldBe Some("heap")
      }

      "declare the pool profile with the headers the page states" in {
          val profiles = MemApiVocab.profiles(Some(docsExampleConfig))
          profiles("acct").headers shouldBe List("acct/pool.h")
          // the built-in profiles survive the merge unchanged
          profiles.keySet shouldBe MemApiVocab.profiles(None).keySet + "acct"
      }

      "decode every documented role at the index the page states" in {
          val entries = MemApiVocab.profiles(Some(docsExampleConfig))("acct").entries
              .map(e => e.name -> e).toMap
          entries("acct_pool_new").region shouldBe Some(
            MemApiVocab.MemRegion("create", arg = Some(1))
          )
          entries("acct_pool_alloc").region shouldBe Some(
            MemApiVocab.MemRegion("allocate", arg = Some(1))
          )
          entries("acct_pool_alloc").len shouldBe Some(2)
          entries("acct_pool_alloc").nullableReturn shouldBe true
          entries("acct_pool_clear").region shouldBe Some(
            MemApiVocab.MemRegion("reset", arg = Some(1))
          )
          entries("acct_pool_delete").region shouldBe Some(
            MemApiVocab.MemRegion("destroy", arg = Some(1))
          )
          entries("acct_pool_get").region shouldBe Some(
            MemApiVocab.MemRegion("allocate", context = Some("acct_current_pool"))
          )
          entries("acct_pool_get").len shouldBe Some(1)
          entries("acct_unref").release shouldBe Some(1)
          entries("acct_ref").acquire shouldBe Some(1)
          entries("acct_take").steal shouldBe Some(1)
          entries("acct_cleanup").cleanup shouldBe true
          entries.values.foreach(e =>
              withClue(s"${e.name}: ") { e.source.exists(_.trim.nonEmpty) shouldBe true }
          )
      }

      "select the profile for a unit including pool.h, matched by basename" in {
          MemApiVocab.selectProfiles(Some(docsExampleConfig), Set("pool.h")).keySet shouldBe
              Set("acct")
          MemApiVocab.selectProfiles(Some(docsExampleConfig), Set("acct/pool.h")).keySet shouldBe
              Set("acct")
          MemApiVocab.selectProfiles(Some(docsExampleConfig), Set("stdio.h")).keySet shouldBe
              Set.empty
      }

      "drop an entry whose documented index is not a number, noting it, and keep the rest" in {
          val broken          = docsExampleConfig.replace("\"release\": 1", "\"release\": \"one\"")
          val (profiles, err) = withCapturedErr(MemApiVocab.profiles(Some(broken)))
          val names           = profiles("acct").entries.map(_.name)
          names should not contain "acct_unref"
          names should contain("acct_ref")
          names should contain("acct_cleanup")
          err should include("acct_unref")
          err should include("release")
      }
  }
end MemApiVocabDocsExampleTests
