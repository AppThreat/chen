package io.appthreat.php2atom.passes

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.shiftleft.semanticcpg.language.*

/** The sinks EasyTagsPass tags in PHP: built-in functions by name, methods by their `->name`. */
class SinkTagsTests extends PhpCode2CpgFixture():

  private val cpg = code("""<?php
      |$id = $_GET["id"];
      |shell_exec("ping " . $id);
      |$r = mysqli_query($conn, "SELECT * FROM users WHERE id = '$id'");
      |$stmt = $db->query("SELECT * FROM t WHERE c = " . $id);
      |include($_GET["page"]);
      |echo $id;
      |header("Location: " . $_GET["next"]);
      |$o = unserialize($_COOKIE["state"]);
      |file_get_contents($_GET["path"]);
      |""".stripMargin)
  new EasyTagsPass(cpg).createAndApply()

  private def tagsOf(name: String): Set[String] = cpg.call.nameExact(name).tag.name.toSet

  "PHP sinks" should {
      "be tagged by family" in {
          (tagsOf("shell_exec") should contain).allOf("code-execution", "shell-exec")
          tagsOf("mysqli_query") should contain("sql")
          tagsOf("query") should contain("sql")
          (tagsOf("include") should contain).allOf("code-execution", "file-io")
          tagsOf("echo") should contain("framework-output")
          tagsOf("header") should contain("framework-output")
          tagsOf("unserialize") should contain("unsafe-deserialization")
          tagsOf("file_get_contents") should contain("file-io")
      }
  }
end SinkTagsTests
