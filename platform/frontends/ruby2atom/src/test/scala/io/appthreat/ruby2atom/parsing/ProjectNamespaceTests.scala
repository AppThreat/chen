package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Classes a Rails project declares in the compact form (`class Api::BaseController`) under its own
  * autoloaded directories are the project's, whatever acronym the project's inflector gives the
  * directory (`activitypub` is `ActivityPub`, `rest` is `REST`). Only what no project file defines
  * is a dependency's.
  */
class ProjectNamespaceTests extends RubyCode2CpgFixture:

  private lazy val cpg = fixture(
    "app/controllers/api/base_controller",
    "app/controllers/concerns/api/rate_limit_headers",
    "app/models/form/account_batch",
    "app/serializers/rest/account_serializer",
    "app/lib/activitypub/tag_manager"
  )

  private def refs =
      cpg.typeRef
          .filter(_.file.name.exists(_.endsWith("api/base_controller.rb")))
          .filterNot(t =>
              t.typeFullName.endsWith("<class>") || t.typeFullName.startsWith("__core") ||
                  t.typeFullName.contains("<lambda>")
          )
          .map(t => (t.lineNumber.get: Int, t.code))
          .l
          .sorted

  "constants under the project's compact-form namespaces are the project's" in {
      val lines = refs.map(_._1)
      lines should not contain 2 // include Api::RateLimitHeaders
      lines should not contain 5 // Form::AccountBatch.new
  }

  "a directory the inflector spells as an acronym still names a project constant" in {
      val lines = refs.map(_._1)
      lines should not contain 6 // REST::AccountSerializer
      lines should not contain 7 // ActivityPub::TagManager.instance
  }

  "a constant no project file defines is still a dependency's" in {
      refs should contain((1, "ApplicationController"))
      refs should contain((8, "Faraday::Utils"))
  }
end ProjectNamespaceTests
