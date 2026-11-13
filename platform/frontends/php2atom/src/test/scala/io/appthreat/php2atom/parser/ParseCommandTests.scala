package io.appthreat.php2atom.parser

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class ParseCommandTests extends AnyWordSpec with Matchers:

  private val Flags = Seq("--with-recovery", "--resolve-names", "-P", "--json-dump")

  "the per-file parse command" should {
      "pass a file name with shell syntax as one argument" in {
          val name = "/project/a$(touch marker);b`id`'c'.php"
          PhpParser.fromPaths("/opt/php-parse", "/opt/php.ini").phpParseCommand(name) shouldBe
              Some(Seq("php", "--php-ini", "/opt/php.ini", "/opt/php-parse") ++ Flags :+ name)
          PhpParser.fromPaths("/opt/phpastgen.js", "/opt/php.ini").phpParseCommand(name) shouldBe
              Some(Seq("node", "/opt/phpastgen.js") ++ Flags :+ name)
      }
  }
