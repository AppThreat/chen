package io.appthreat.x2cpg.frontendspecific.ruby2atom

import io.shiftleft.codepropertygraph.generated.nodes.NewMethod
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.util.regex.Pattern

/** The prefix index ImplicitRequirePass looks a module's methods up with gives the methods the
  * regex scan `fullName(quote(prefix) + ".*")` gave, in the same order.
  */
class ImplicitRequirePrefixIndexTests extends AnyWordSpec with Matchers:

  // graph order differs from name order, and one name appears twice
  private val names = List(
    "app/a.rb:<main>.B.run",
    "app/a.rb:<main>",
    "app/a.rb:<main>.A.<body>",
    "app/a.rb:<main>.A",
    "app/a.rb:<main>.Ab.go",
    "app/a.rb:<main>.A.go",
    "app/a.rb:<main>.A",
    "app/b.rb:<main>",
    "app/a.rb:<main>.A.go.<lambda>0"
  )

  private val cpg = MockCpg().withCustom { (graph, _) =>
      names.foreach(n => graph.addNode(NewMethod().name(n.split('.').last).fullName(n)))
  }.cpg

  private val index = ImplicitRequirePass.PrefixIndex(cpg.method.l)(_.fullName)

  "the prefix index" should {
      "find what the regex scan finds, in graph order" in {
          List("app/a.rb:<main>", "app/a.rb:<main>.A", "app/a.rb:<main>.A.go", "app/b.rb:<main>")
              .foreach { prefix =>
                  index.withPrefix(prefix).map(_.id()).toList shouldBe
                      cpg.method.fullName(Pattern.quote(prefix) + ".*").map(_.id()).l
              }
      }

      "find nothing for a prefix no name starts with, below or above every name" in {
          index.withPrefix("app/0").toList shouldBe Nil
          index.withPrefix("app/z").toList shouldBe Nil
          index.withPrefix("app/a.rb:<main>.C").toList shouldBe Nil
      }
  }
end ImplicitRequirePrefixIndexTests
