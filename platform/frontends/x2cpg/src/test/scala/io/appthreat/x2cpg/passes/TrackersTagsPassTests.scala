package io.appthreat.x2cpg.passes

import io.appthreat.x2cpg.passes.taggers.TrackersTagsPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewIdentifier}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class TrackersTagsPassTests extends AnyWordSpec with Matchers {

  import TrackersTagsPassTests.Fixture

  "TrackersTagsPass" should {

    "load tracker definitions from the bundled resource" in {
      TrackersTagsPass.Trackers.size should be > 400
    }

    "tag an Android AppsFlyer call as a tracker" in
      Fixture(Languages.JAVASRC, calls = Seq("com.appsflyer.AppsFlyerLib.start")) { cpg =>
        val tags = cpg.call.methodFullName("com.appsflyer.*").tag.name.toSet
        tags should contain("tracker")
        tags should contain("tracker:AppsFlyer")
        tags should contain("tracker-analytics")
      }

    "tag an Android ad SDK identifier as adware" in
      Fixture("ANDROID", identifiers = Seq("com.ad4screen.sdk.A4S")) { cpg =>
        val tags = cpg.identifier.typeFullName("com.ad4screen.*").tag.name.toSet
        tags should contain("tracker")
        tags should contain("adware")
        tags should contain("tracker-advertisement")
      }

    "not tag unrelated application code" in
      Fixture(Languages.JAVASRC, identifiers = Seq("com.myapp.service.UserService")) { cpg =>
        cpg.identifier.typeFullName("com.myapp.*").tag shouldBe empty
      }

    "tag a JavaScript analytics package import" in
      Fixture(Languages.JSSRC, identifiers = Seq("mixpanel-browser:Mixpanel")) { cpg =>
        val tags = cpg.identifier.typeFullName("mixpanel-browser.*").tag.name.toSet
        tags should contain("tracker")
        tags should contain("tracker:Mixpanel")
      }
  }
}

object TrackersTagsPassTests {

  private object Fixture {
    def apply[T](
      language: String,
      calls: Seq[String] = Seq.empty,
      identifiers: Seq[String] = Seq.empty
    )(fun: Cpg => T): T = {
      val cpg = MockCpg().withMetaData(language, Nil).withCustom { (graph, _) =>
        calls.foreach { mfn =>
          graph.addNode(NewCall().name(mfn.split('.').last).methodFullName(mfn).code(mfn))
        }
        identifiers.foreach { tfn =>
          graph.addNode(NewIdentifier().name(tfn.split("[.:]").last).typeFullName(tfn).code(tfn))
        }
      }.cpg
      new TrackersTagsPass(cpg).createAndApply()
      fun(cpg)
    }
  }
}
