package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.Config
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Migrations are Ruby that uses gems (`ActiveRecord::Migration[7.2]`), so they are scanned; specs,
  * tests and vendored code are not.
  */
class DefaultIgnoreTests extends AnyWordSpec with Matchers:

  private def ignored(path: String): Boolean =
      Config().defaultIgnoredFilesRegex.exists(_.findFirstIn(path).isDefined)

  "the default ignore patterns" should {
      "leave migrations in, with either path separator" in {
          ignored("db/migrate/20240101_create_accounts.rb") shouldBe false
          ignored("db\\post_migrate\\20240101_x.rb") shouldBe false
      }
      "still skip specs, tests and vendored code" in {
          ignored("spec/models/user_spec.rb") shouldBe true
          ignored("app/test/helper.rb") shouldBe true
          ignored("vendor/bundle/x.rb") shouldBe true
      }
  }
