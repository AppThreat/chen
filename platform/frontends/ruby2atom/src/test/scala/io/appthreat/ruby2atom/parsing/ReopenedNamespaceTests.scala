package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** A project can reopen a gem's namespace (`module Paperclip; class Transcoder`) without defining
  * it. A module that only nests classes and modules has no methods and no constants of its own, so
  * what is called on it, or looked up under it, and the project does not define, is the gem's. A
  * class, and a module with content, is the project's whole.
  */
class ReopenedNamespaceTests extends RubyCode2CpgFixture:

  private lazy val cpg = fixture("callsites/reopened")

  private def refs =
      cpg.typeRef.filterNot(t =>
          t.typeFullName.endsWith("<class>") || t.typeFullName.contains("<lambda>")
      ).map(t => (t.lineNumber.get: Int, t.code, t.typeFullName)).l.sorted

  "what a nesting-only namespace is asked for and the project does not define is a dependency's" in {
      refs should contain((24, "Paperclip::Attachment", "Paperclip.Attachment"))
      refs should contain((25, "Chewy", "Chewy"))
  }

  "what the project defines under that namespace, and a module with content, are the project's" in {
      val lines = refs.map(_._1)
      lines should not contain 26 // Chewy::Strategy::Mine
      lines should not contain 27 // Solid.helper
      lines should not contain 29 // Paperclip::Transcoder
  }

  "what the project does not define under a module or class of its own is a dependency's" in {
      // `Solid` is the project's, but nothing under it named Missing: a project that defines Solid
      // alone could not run this, so something else, a gem that reopens it, defines it
      refs should contain((32, "Solid::Missing", "Solid.Missing"))
  }

  "an empty module is a namespace too, so calling on it reaches outside" in {
      refs should contain((28, "Marker", "Marker"))
  }

  "a bare mention of a namespace the project nests in is the project's" in {
      val lines = refs.map(_._1)
      lines should not contain 30 // include Marker
      lines should not contain 31 // [Paperclip, Marker]
  }
end ReopenedNamespaceTests
