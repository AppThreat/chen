package io.appthreat.php2atom.parser

import better.files.File
import io.appthreat.x2cpg.utils.ExternalCommand
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.compiletime.uninitialized
import scala.util.{Success, Try}

/** The files the frontend ignores (a Composer `vendor/` tree) are not handed to the batch generator
  * to parse: it receives the ignore pattern as its exclusion, and without one it is asked for the
  * whole tree as before.
  */
class IgnoredFilesBatchTests extends AnyWordSpec with Matchers with BeforeAndAfterAll:

  private val phpAvailable: Boolean =
      Try(ExternalCommand.run("php --version", ".", true)) match
        case Success(Success(_)) => true
        case _                   => false

  private var workRoot: File = uninitialized

  override def beforeAll(): Unit =
      if phpAvailable then workRoot = File.newTemporaryDirectory("ignored-files-batch-")

  override def afterAll(): Unit =
      if workRoot != null then Try(workRoot.delete(swallowIOExceptions = true))

  /** A stub generator that writes the arguments it was given next to itself. */
  private def argumentsGiven(ignoredFilesRegex: String): List[String] =
    val dir = (workRoot / s"gen-${ignoredFilesRegex.hashCode.abs}").createDirectoryIfNotExists()
    val argsFile = dir / "args.txt"
    val bin      = dir / "stubgen.php"
    bin.writeText(s"""<?php
        |if (in_array("--parser-info", $$argv, true)) { echo "Generator version: 2.0.0\\n"; exit(0); }
        |file_put_contents("${argsFile.canonicalPath}", implode("\\n", array_slice($$argv, 1)));
        |exit(0);
        |""".stripMargin)
    val ini = dir / "php.ini"
    ini.writeText("memory_limit = -1")
    val input = (dir / "in").createDirectoryIfNotExists()
    PhpParser.fromPaths(bin.canonicalPath, ini.canonicalPath, None, ignoredFilesRegex)
        .parseDirectory(input.canonicalPath, (dir / "out").canonicalPath)
    argsFile.contentAsString.split("\n").toList

  "the batch generator" should {
      "be told to leave out the files the frontend ignores" in {
          if !phpAvailable then cancel("No PHP runtime available on this platform")
          val regex = "(.*/)?vendor/.*"
          val args  = argumentsGiven(regex)
          args should contain("--include-vendor")
          args.dropWhile(_ != "--exclude").drop(1).headOption shouldBe Some(regex)
      }

      "be asked for the whole tree when nothing is ignored (twin)" in {
          if !phpAvailable then cancel("No PHP runtime available on this platform")
          val args = argumentsGiven("")
          args.dropWhile(_ != "--exclude").drop(1).headOption shouldBe Some("\\b\\B")
      }
  }
end IgnoredFilesBatchTests
