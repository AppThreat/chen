package io.appthreat.x2cpg.passes

import io.appthreat.x2cpg.passes.taggers.AndroidServicesTagsPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Languages}
import io.shiftleft.codepropertygraph.generated.nodes.{NewCall, NewIdentifier, NewLiteral}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.testing.MockCpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class AndroidServicesTagsPassTests extends AnyWordSpec with Matchers {

  import AndroidServicesTagsPassTests.Fixture

  "AndroidServicesTagsPass" should {

    "load service definitions from the bundled resource" in {
      AndroidServicesTagsPass.Services.size should be > 40
    }

    "tag a call into an AI/LLM SDK and its arguments" in
      Fixture(Languages.JAVASRC, callWithArg = Some(("com.openai.client.OpenAiService.createChatCompletion", "\"prompt text\""))) { cpg =>
        val callTags = cpg.call.methodFullName("com.openai.*").tag.name.toSet
        callTags should contain("service-egress")
        callTags should contain("service-ai-llm")
        callTags should contain("service:OpenAI")
        // the literal argument is tagged at the call-argument level
        cpg.literal.code("\"prompt text\"").tag.name.toSet should contain("service-egress")
      }

    "tag a literal containing a cloud service host" in
      Fixture("JIMPLE", literals = Seq("\"https://my-app.firebaseio.com/users.json\"")) { cpg =>
        val tags = cpg.literal.code(".*firebaseio.*").tag.name.toSet
        tags should contain("service-egress")
        tags should contain("service-cloud")
        tags should contain("service:Firebase")
      }

    "tag a literal pointing at a social network API" in
      Fixture(Languages.JAVASRC, literals = Seq("\"https://graph.facebook.com/me\"")) { cpg =>
        cpg.literal.code(".*facebook.*").tag.name.toSet should contain("service-social")
      }

    "tag an http data-sending call and its argument, but not the client surface" in
      Fixture(
        Languages.JAVASRC,
        callWithArg = Some(("okhttp3.Request.Builder.post", "\"payload\"")),
        identifiers = Seq("okhttp3.OkHttpClient")
      ) { cpg =>
        // the client object identifier is NOT tagged (too noisy)
        cpg.identifier.typeFullName("okhttp3.*").tag shouldBe empty
        // but a data-sending call ("create") and its argument are tagged
        val callTags = cpg.call.methodFullName("okhttp3.*").tag.name.toSet
        callTags should contain("service-http")
        cpg.literal.code("\"payload\"").tag.name.toSet should contain("service-egress")
      }

    "not tag a non-egress http client call" in
      Fixture(Languages.JAVASRC, callWithArg = Some(("okhttp3.OkHttpClient.connectTimeout", "\"30\""))) { cpg =>
        cpg.call.methodFullName("okhttp3.*").tag shouldBe empty
      }

    "tag a newly-added ML/AI cloud SDK call" in
      Fixture(Languages.JAVASRC, callWithArg = Some(("com.google.mlkit.vision.text.TextRecognizer.process", "image"))) { cpg =>
        cpg.call.methodFullName("com.google.mlkit.*").tag.name.toSet should contain("service-ai-llm")
      }

    "tag a Chinese cloud SDK identifier" in
      Fixture(Languages.JAVASRC, identifiers = Seq("com.aliyun.oss.OSSClient")) { cpg =>
        val tags = cpg.identifier.typeFullName("com.aliyun.*").tag.name.toSet
        tags should contain("service-cloud")
        tags should contain("service:Alibaba Cloud")
      }

    "do nothing for non-jvm frontends" in
      Fixture(Languages.PYTHON, literals = Seq("\"https://api.openai.com/v1/chat\"")) { cpg =>
        cpg.literal.code(".*openai.*").tag shouldBe empty
      }

    "not tag unrelated literals" in
      Fixture(Languages.JAVASRC, literals = Seq("\"hello world\"")) { cpg =>
        cpg.literal.code(".*hello.*").tag shouldBe empty
      }
  }
}

object AndroidServicesTagsPassTests {

  private object Fixture {
    def apply[T](
      language: String,
      literals: Seq[String] = Seq.empty,
      identifiers: Seq[String] = Seq.empty,
      callWithArg: Option[(String, String)] = None
    )(fun: Cpg => T): T = {
      val cpg = MockCpg().withMetaData(language, Nil).withCustom { (graph, _) =>
        literals.foreach { code =>
          graph.addNode(NewLiteral().code(code).typeFullName("java.lang.String"))
        }
        identifiers.foreach { tfn =>
          graph.addNode(NewIdentifier().name(tfn.split("[.:]").last).typeFullName(tfn).code(tfn))
        }
        callWithArg.foreach { case (mfn, argCode) =>
          val call = NewCall().name(mfn.split('.').last).methodFullName(mfn).code(mfn)
          val arg  = NewLiteral().code(argCode).typeFullName("java.lang.String").argumentIndex(1)
          graph.addNode(call)
          graph.addNode(arg)
          graph.addEdge(call, arg, EdgeTypes.ARGUMENT)
          graph.addEdge(call, arg, EdgeTypes.AST)
        }
      }.cpg
      new AndroidServicesTagsPass(cpg).createAndApply()
      fun(cpg)
    }
  }
}
