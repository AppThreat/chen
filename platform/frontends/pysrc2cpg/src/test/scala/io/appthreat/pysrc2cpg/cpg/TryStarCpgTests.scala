package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.codepropertygraph.generated.NodeTypes
import io.shiftleft.semanticcpg.language.*

class TryStarCpgTests extends PySrc2CpgFixture():
  "try star support tests" should {
      "TryStar statement with except*" in {
          val cpg = code(
            """def handle_exception_group():
                           |    try:
                           |        user_input = get_user_input()
                           |        process(user_input)
                           |    except* ValueError as e:
                           |        for error in e.exceptions:
                           |            sink(error)
                           |    except* TypeError as e:
                           |        for error in e.exceptions:
                           |            sink(error)""".stripMargin,
            "test.py"
          )
          cpg.call("get_user_input").head.code shouldBe "get_user_input()"
          cpg.call("process").head.code shouldBe "process(user_input)"
          cpg.call("sink").head.code shouldBe "sink(error)"
      }
      "TryStar statement with finally" in {
          val cpg = code(
            """def handle_exception_group():
                           |    try:
                           |        user_input = get_user_input()
                           |        process(user_input)
                           |    except* ValueError as e:
                           |        for er in e.exceptions:
                           |            sink(er)
                           |    finally:
                           |        sink("foo")""".stripMargin,
            "test.py"
          )
          cpg.call("get_user_input").head.code shouldBe "get_user_input()"
          cpg.call("process").head.code shouldBe "process(user_input)"
          cpg.call("sink").last.code shouldBe "sink(\"foo\")"
      }
      "TryStar statement with else" in {
          val cpg = code(
            """def handle_exception_group():
                           |    try:
                           |        user_input = get_user_input()
                           |        process(user_input)
                           |    except* ValueError as e:
                           |        for er in e.exceptions:
                           |            sink(er)
                           |    else:
                           |        sink("foo")""".stripMargin,
            "test.py"
          )
          cpg.call("get_user_input").head.code shouldBe "get_user_input()"
          cpg.call("process").head.code shouldBe "process(user_input)"
          cpg.call("sink").last.code shouldBe "sink(\"foo\")"
      }
      "TryStar statement with try mixed" in {
          val cpg = code(
            """def handle_mixed_exceptions():
                           |    try:
                           |        user_input = get_user_input()
                           |        process(user_input)
                           |    except* ValueError as e:
                           |        handle_value_errors(e)
                           |
                           |    try:
                           |        file_data = read_file()
                           |        process_file(file_data)
                           |    except IOError as e:
                           |        handle_io_error(e)
                           |
                           |    sink(user_input, file_data)""".stripMargin,
            "test.py"
          )
          cpg.call("get_user_input").head.code shouldBe "get_user_input()"
          cpg.call("process").head.code shouldBe "process(user_input)"
          cpg.call("handle_value_errors").head.code shouldBe "handle_value_errors(e)"
          cpg.call("handle_io_error").last.code shouldBe "handle_io_error(e)"
          cpg.call("sink").last.code shouldBe "sink(user_input, file_data)"
      }
  }
end TryStarCpgTests
