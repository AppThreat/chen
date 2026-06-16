package io.appthreat.x2cpg.passes

import io.appthreat.x2cpg.passes.taggers.PiiTagsPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{NewLiteral, NewMethodParameterIn}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class PiiTagsPassTests extends AnyWordSpec with Matchers {

  import PiiTagsPassTests.Fixture

  "PiiTagsPass" should {

    "tag an email literal" in Fixture(literals = Seq("\"alice@example.com\"")) { cpg =>
      val tags = cpg.literal.code("\"alice@example.com\"").tag.name.toSet
      tags should contain("pii-email")
      tags should contain("sensitive-data")
      tags should contain("gdpr")
    }

    "tag a Luhn-valid credit card literal as PCI data" in Fixture(literals = Seq("\"4111111111111111\"")) { cpg =>
      val tags = cpg.literal.code("\"4111111111111111\"").tag.name.toSet
      tags should contain("pci-card-number")
      tags should contain("pci-dss")
    }

    "not tag a digit string that fails the Luhn check" in Fixture(literals = Seq("\"4111111111111112\"")) { cpg =>
      cpg.literal.code("\"4111111111111112\"").tag.name.toSet should not contain "pci-card-number"
    }

    "tag a valid US SSN literal" in Fixture(literals = Seq("\"123-45-6789\"")) { cpg =>
      cpg.literal.code("\"123-45-6789\"").tag.name.toSet should contain("pii-us-ssn")
    }

    "not tag an invalid SSN with area 000" in Fixture(literals = Seq("\"000-45-6789\"")) { cpg =>
      cpg.literal.code("\"000-45-6789\"").tag.name.toSet should not contain "pii-us-ssn"
    }

    "tag a parameter named ssn" in Fixture(parameters = Seq("ssn")) { cpg =>
      cpg.parameter.name("ssn").tag.name.toSet should contain("pii-us-ssn")
    }

    "tag a parameter named password as a secret" in Fixture(parameters = Seq("password")) { cpg =>
      val tags = cpg.parameter.name("password").tag.name.toSet
      tags should contain("secret-credential")
      tags should contain("secret")
    }

    "tag a parameter named firstName" in Fixture(parameters = Seq("firstName")) { cpg =>
      cpg.parameter.name("firstName").tag.name.toSet should contain("pii-full-name")
    }

    "not tag the implicit self/this parameter" in Fixture(parameters = Seq("self")) { cpg =>
      cpg.parameter.name("self").tag shouldBe empty
    }

    "not tag a benign literal" in Fixture(literals = Seq("\"hello world\"")) { cpg =>
      cpg.literal.code("\"hello world\"").tag shouldBe empty
    }
  }
}

object PiiTagsPassTests {

  private object Fixture {
    def apply[T](literals: Seq[String] = Seq.empty, parameters: Seq[String] = Seq.empty)(
      fun: Cpg => T
    ): T = {
      val cpg = MockCpg().withCustom { (graph, _) =>
        literals.foreach { code =>
          graph.addNode(NewLiteral().code(code).typeFullName("string"))
        }
        parameters.foreach { name =>
          graph.addNode(NewMethodParameterIn().name(name).code(name).typeFullName("ANY"))
        }
      }.cpg
      new PiiTagsPass(cpg).createAndApply()
      fun(cpg)
    }
  }
}
