package io.appthreat.x2cpg

import better.files._
import io.appthreat.x2cpg.utils.IgnoreInWindows
import io.shiftleft.utils.ProjectRoot
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatest.Inside

import java.nio.file.attribute.PosixFilePermissions
import scala.jdk.CollectionConverters._
import scala.util.Try
import java.io.FileNotFoundException

class SourceFilesTests extends AnyWordSpec with Matchers with Inside {

  val cSourceFileExtensions = Set(".c", ".h")
  val resourcesRoot         = ProjectRoot.relativise("platform/frontends/x2cpg/src/main/resources")

  "determine source files" when {

    "using regular input file" in {
      SourceFiles.determine(s"$resourcesRoot/testcode/main.c", cSourceFileExtensions).size shouldBe 1
    }

    "using regular input directory" in {
      SourceFiles.determine(s"$resourcesRoot/testcode", cSourceFileExtensions).size shouldBe 3
    }

    "input is symlink to file" in {
      SourceFiles.determine(s"$resourcesRoot/symlink-to-main.c", cSourceFileExtensions).size shouldBe 1
    }
  }

  "throw an exception" when {

    "the input file does not exist" in {
      val result = Try(SourceFiles.determine("path/to/nothing/", cSourceFileExtensions))
      result.isFailure shouldBe true
      result.failed.get shouldBe a[FileNotFoundException]
    }

    "the input file exists, but is not readable" taggedAs IgnoreInWindows in {
      File.usingTemporaryFile() { tmpFile =>
        tmpFile.setPermissions(PosixFilePermissions.fromString("-wx-w--w-").asScala.toSet)
        tmpFile.exists shouldBe true
        tmpFile.isReadable shouldBe false

        val result = Try(SourceFiles.determine(tmpFile.canonicalPath, cSourceFileExtensions))
        result.isFailure shouldBe true
        result.failed.get shouldBe a[FileNotFoundException]
      }
    }
  }
}
