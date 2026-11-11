package io.appthreat.x2cpg.parse

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files

class ParseReporterTests extends AnyWordSpec with Matchers:

  "ParseReporter when disabled" should {

      "store nothing and not even evaluate the message" in {
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          ParseReporter.isEnabled shouldBe false
          var messagesBuilt = 0
          ParseReporter.record(
            ParseReporter.Frontend.Ruby,
            "app/models/user.rb",
            ParseReporter.Outcome.Unparsed,
            ParseReporter.Stage.Parse,
            { messagesBuilt += 1; "should not happen" }
          )
          messagesBuilt shouldBe 0
          ParseReporter.records shouldBe empty
      }
  }

  "ParseReporter when enabled" should {

      "keep the record with its fields and `/` separators" in {
          val tmp = Files.createTempDirectory("parse-reporter")
          System.setProperty("chen.parse.report", tmp.resolve("unused.json").toString)
          try
            ParseReporter.reset()
            ParseReporter.isEnabled shouldBe true
            ParseReporter.record(
              ParseReporter.Frontend.JsSrc,
              "src\\lib\\broken.js",
              ParseReporter.Outcome.Unparsed,
              ParseReporter.Stage.Parse,
              "Unexpected token (3:8)"
            )
            ParseReporter.records shouldBe List(
              ParseFailureRecord(
                "jssrc",
                "src/lib/broken.js",
                "unparsed",
                "parse",
                "Unexpected token (3:8)"
              )
            )
          finally
            System.clearProperty("chen.parse.report")
            ParseReporter.reset()
          end try
      }

      "collapse newlines and cap the message at 500 characters" in {
          val tmp = Files.createTempDirectory("parse-reporter")
          System.setProperty("chen.parse.report", tmp.toString)
          try
            ParseReporter.reset()
            val long = ("x" * 600)
            ParseReporter.record(
              ParseReporter.Frontend.C,
              "src/huge.c",
              ParseReporter.Outcome.Dropped,
              ParseReporter.Stage.Ast,
              s"line one\nline two\r\n$long"
            )
            val message = ParseReporter.records.head.message
            message should startWith("line one line two ")
            // the cap astgen uses for its own manifest records
            message should have size 500
            message should not contain "\n"
          finally
            System.clearProperty("chen.parse.report")
            ParseReporter.reset()
      }

      "sort records by file and start from empty after reset" in {
          val tmp = Files.createTempDirectory("parse-reporter")
          System.setProperty("chen.parse.report", tmp.toString)
          try
            ParseReporter.reset()
            ParseReporter.record(
              ParseReporter.Frontend.Python,
              "zzz.py",
              ParseReporter.Outcome.Partial,
              ParseReporter.Stage.Parse,
              "b"
            )
            ParseReporter.record(
              ParseReporter.Frontend.JavaSrc,
              "aaa.java",
              ParseReporter.Outcome.Dropped,
              ParseReporter.Stage.Ast,
              "a"
            )
            ParseReporter.records.map(_.file) shouldBe List("aaa.java", "zzz.py")
            ParseReporter.reset()
            ParseReporter.records shouldBe empty
          finally
            System.clearProperty("chen.parse.report")
            ParseReporter.reset()
          end try
      }
  }

  "relativeTo" should {

      "render the path relative to the root with `/` separators" in {
          val tmp       = Files.createTempDirectory("parse-reporter-rel")
          val sourceDir = Files.createDirectories(tmp.resolve("lib/pkg"))
          val file      = sourceDir.resolve("A.java")
          Files.writeString(file, "class A {}")
          ParseReporter.relativeTo(tmp.toString, file.toString) shouldBe "lib/pkg/A.java"
      }

      "leave a path outside the root alone, with separators normalized" in {
          ParseReporter.relativeTo("/elsewhere/root", "/somewhere\\else\\B.rb") shouldBe
              "/somewhere/else/B.rb"
      }
  }
end ParseReporterTests
