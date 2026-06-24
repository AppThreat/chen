package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.JsSrc2Cpg
import io.appthreat.jssrc2cpg.testfixtures.JsSrc2CpgFrontend
import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, TestCpg}
import io.shiftleft.semanticcpg.language._

class ImportsPassTests extends Code2CpgFixture(() => new TestCpgWithoutDataFlow()) {

  "ImportsPass" should {
    "create IMPORT node for declaration" in {
      val cpg = code("""
          |var barOrBaz = require('./bar.js');
          |""".stripMargin)

      val List(x) = cpg.imports.l
      x.importedEntity shouldBe Some("./bar.js")
      x.importedAs shouldBe Some("barOrBaz")
      val List(call) = x.call.l
      call.code shouldBe "require('./bar.js')"
      val List(assignment) = call.inAssignment.l
      assignment.code shouldBe "var barOrBaz = require('./bar.js')"
      assignment.target.code shouldBe "barOrBaz"
      val source = assignment.source
      source shouldBe call
    }

    "create IMPORT node for assignment from require" in {
      val cpg = code("""
          |barOrBaz = require('./bar.js');
          |""".stripMargin)
      val List(x) = cpg.imports.l
      x.importedEntity shouldBe Some("./bar.js")
      x.importedAs shouldBe Some("barOrBaz")
      val List(call) = x.call.l
      call.code shouldBe "require('./bar.js')"
      val List(assignment) = call.inAssignment.l
      assignment.code shouldBe "barOrBaz = require('./bar.js')"
      assignment.target.code shouldBe "barOrBaz"
      val source = assignment.source
      source shouldBe call
    }

    "record the bare package specifier when requiring a third-party module" in {
      val cpg = code("""
          |var Vue = require('vue');
          |""".stripMargin)
      val List(x) = cpg.imports.l
      x.importedEntity shouldBe Some("vue")
      x.importedAs shouldBe Some("Vue")
    }
  }

  "ESM imports" should {
    "record a default import as <package>:<name>" in {
      val cpg = code("""
          |import Vue from 'vue';
          |""".stripMargin)
      val List(x) = cpg.imports.l
      x.importedEntity shouldBe Some("vue:Vue")
      x.importedAs shouldBe Some("Vue")
    }

    "record a named import as <package>:<name>" in {
      val cpg = code("""
          |import { useRoute } from 'vue-router';
          |""".stripMargin)
      val List(x) = cpg.imports.l
      x.importedEntity shouldBe Some("vue-router:useRoute")
      x.importedAs shouldBe Some("useRoute")
    }

    "record a namespace import as <package>:<name>" in {
      val cpg = code("""
          |import * as Vue from 'vue';
          |""".stripMargin)
      val List(x) = cpg.imports.l
      x.importedEntity shouldBe Some("vue:Vue")
      x.importedAs shouldBe Some("Vue")
    }

    "record a side-effect-only import as the bare specifier" in {
      val cpg = code("""
          |import 'vue';
          |""".stripMargin)
      val List(x) = cpg.imports.l
      x.importedEntity shouldBe Some("vue")
    }

    "record a scoped package import preserving the scope" in {
      val cpg = code("""
          |import { ref } from '@vue/composition-api';
          |""".stripMargin)
      val List(x) = cpg.imports.l
      x.importedEntity shouldBe Some("@vue/composition-api:ref")
      x.importedAs shouldBe Some("ref")
    }
  }
}

class TestCpgWithoutDataFlow extends TestCpg with JsSrc2CpgFrontend {
  override val fileSuffix: String = ".js"
  override def applyPasses(): Unit = {
    X2Cpg.applyDefaultOverlays(this)
    JsSrc2Cpg.postProcessingPasses(this).foreach(_.createAndApply())
  }
}
