package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.shiftleft.semanticcpg.language.*

/** The sinks EasyTagsPass tags in a Rails controller (`resources/ruby/sinks.rb`). */
class SinkTagsTests extends RubyCode2CpgFixture:

  private lazy val cpg =
    val built = fixture("sinks")
    new EasyTagsPass(built).createAndApply()
    built

  private def tagsOf(code: String): Set[String] =
      cpg.call.codeExact(code).tag.name.toSet

  "Ruby sinks" should {
      "tag commands" in {
          (tagsOf("system(\"ls #{id}\")") should contain).allOf("code-execution", "shell-exec")
          (tagsOf("`cat #{id}`") should contain).allOf("code-execution", "shell-exec")
          tagsOf("IO.popen(params[:cmd])") should contain("shell-exec")
          tagsOf("(<tmp-7> = Open3).capture2(\"git\", params[:ref])") should contain("shell-exec")
          tagsOf("eval(params[:code])") should contain("code-execution")
      }

      "tag SQL given as text, not as keywords" in {
          cpg.call.nameExact("where").l.map(c =>
              c.code -> c.tag.name.toSet.contains("sql")
          ) shouldBe
              List(
                "(<tmp-0> = User).where(\"id = '#{id}'\")" -> true,
                "(<tmp-1> = User).where(id: id)"           -> false
              )
          cpg.call.nameExact("execute").tag.name.l should contain("sql")
      }

      "tag deserialisation, files, reflection and output" in {
          tagsOf("Marshal.load(Base64.decode64(params[:data]))") should contain(
            "unsafe-deserialization"
          )
          tagsOf("File.open(params[:path])") should contain("file-io")
          tagsOf("send_file params[:file]") should contain("file-io")
          // without arguments or parentheses a call is lowered as a field access
          tagsOf("(<tmp-3> = params[:klass]).constantize") should contain("reflection")
          cpg.call.nameExact("send").l.map(c =>
              c.code -> c.tag.name.toSet.contains("reflection")
          ) shouldBe
              List(
                "(<tmp-4> = current_user).send(params[:m])"               -> true,
                "(<tmp-6> = ActiveRecord::Base).send(:include, Auditing)" -> false
              )
          tagsOf("redirect_to params[:url]") should contain("framework-output")
          tagsOf("redirect_to \"/home\"") should not contain "framework-output"
          tagsOf("redirect_to root_url") should not contain "framework-output"
          tagsOf("render inline: params[:tpl]") should contain("template-injection")
          tagsOf("render \"show\"") should not contain "template-injection"
          tagsOf("(<tmp-11> = params[:html]).html_safe") should contain("framework-output")
      }
  }
end SinkTagsTests
