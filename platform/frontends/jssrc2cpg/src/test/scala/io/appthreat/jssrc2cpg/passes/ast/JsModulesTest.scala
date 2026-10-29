package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.js.{
    ImportKind,
    JsFrameworkRecognizersPass,
    JsModules,
    JsStats
}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** The import queries of the JS taggers. The memoised answers must equal what filtering the file's
  * imports gives, and the work behind them must follow the number of (file, package) pairs, never
  * the number of calls.
  */
class JsModulesTest extends DataFlowCodeToCpgSuite:

  /** Every import shape: named and renamed, default, namespace, side effect, `require` and
    * destructured `require`, scoped packages and subpaths, alias pseudo-packages, relative imports,
    * and one package under different local names in two files.
    */
  private def fixture(): Cpg =
      code(
        """
      |import { exec as run, spawn } from 'child_process';
      |import cp from 'node:child_process';
      |import * as fs from 'fs';
      |import 'reflect-metadata';
      |const { execSync: shell, fork = noop } = require('child_process');
      |const axios = require('axios');
      |run(shell('ls')); cp.exec(axios.get('u')); fs.readFile('p'); spawn('x');
      |""".stripMargin,
        "src/a.js"
      ).moreCode(
        """
      |import { Controller, Get as G } from '@nestjs/common';
      |import { Body } from '@nestjs/common/dto';
      |import { useRouter, redirect } from 'next/navigation';
      |import { page } from '$app/stores';
      |import { x } from '#imports';
      |import { y } from './a';
      |import axios, { create as make } from 'axios';
      |import { exec } from 'child_process';
      |@Controller() class K { @G() h(@Body() b) { return exec(axios.get(page.url)) + make() + y(x); } }
      |""".stripMargin,
        "src/b.ts"
      ).moreCode(
        """
      |import cps from 'child_process';
      |import { exec as e2 } from 'child_process';
      |import DOMPurify from 'dompurify';
      |e2(cps.exec(DOMPurify.sanitize(location.hash)));
      |""".stripMargin,
        "src/c.js"
      )

  private val Names = Seq(
    "exec",
    "spawn",
    "execSync",
    "fork",
    "Get",
    "Controller",
    "page",
    "create",
    "default",
    "z",
    "no-such-name"
  )
  private val Wanted = Seq(
    "child_process",
    "fs",
    "axios",
    "@nestjs",
    "@nestjs/common",
    "next",
    "next/navigation",
    "$app",
    "$app/stores",
    "#imports",
    "dompurify",
    "reflect-metadata",
    "./a",
    "node",
    "unknown"
  )

  "JsModules" should {

      "answer every (file, package, name) triple as filtering the imports does" in {
          val cpg   = fixture()
          val m     = new JsModules(cpg)
          val files = cpg.file.name.l :+ "no/such/file.js"
          (m.imports.map(_.kind).toSet should contain).allOf(
            ImportKind.Named,
            ImportKind.Default,
            ImportKind.Namespace,
            ImportKind.SideEffect,
            ImportKind.Require
          )
          (m.imports.flatMap(_.packageName).toSet should contain).allOf(
            "child_process",
            "@nestjs/common",
            "next",
            "$app",
            "#imports",
            "axios"
          )
          (files.flatMap(f => Wanted.map(f -> _))).foreach { (f, pkg) =>
            val all = m.imports.filter(_.file == f)
                .filter(_.packageName.exists(JsModules.packageMatches(_, pkg)))
            withClue(s"module bindings of $f/$pkg: ") {
                m.moduleBindingsOf(f, pkg) shouldBe
                    all.filter(i => i.kind != ImportKind.Named && i.kind != ImportKind.SideEffect)
                        .map(_.local).toSet
            }
            withClue(s"named locals of $f/$pkg: ") {
                m.namedLocalsOf(f, pkg) shouldBe
                    all.filter(_.kind == ImportKind.Named).map(_.local).toSet
            }
            Names.foreach { n =>
                withClue(s"local names of $f/$pkg/$n: ") {
                    m.localNamesOf(f, pkg, n) shouldBe
                        all.filter(i => i.kind == ImportKind.Named && i.imported == n)
                            .map(_.local).toSet
                }
            }
            m.importsAny(f, Seq(pkg)) shouldBe all.nonEmpty
          }
          // the memo answers the same the second time
          m.localNamesOf("src/a.js", "child_process", "exec") shouldBe Set("run")
          m.localNamesOf("src/b.ts", "child_process", "exec") shouldBe Set("exec")
          m.localNamesOf("src/c.js", "child_process", "exec") shouldBe Set("e2")
          m.moduleBindingsOf("src/a.js", "child_process") should contain("cp")
          m.localNamesOf("src/a.js", "child_process", "execSync") shouldBe Set("shell")
      }

      "resolve every local name as finding it in the file's imports does" in {
          val cpg    = fixture()
          val m      = new JsModules(cpg)
          val locals = m.imports.map(_.local).toSet + "no-such-local" + ""
          (cpg.file.name.l :+ "none.js").foreach { f =>
              locals.foreach { l =>
                  withClue(s"$f/$l: ") {
                      m.resolve(f, l) shouldBe m.imports.filter(_.file == f).find(_.local == l)
                  }
              }
          }
      }

      "answer the files and modules a package or specifier is imported by" in {
          val cpg = fixture()
          val m   = new JsModules(cpg)
          Wanted.foreach { p =>
              m.filesImporting(p) shouldBe m.imports
                  .filter(_.packageName.exists(JsModules.packageMatches(_, p))).map(_.file).toSet
          }
          m.filesImporting("axios", "dompurify") shouldBe Set("src/a.js", "src/b.ts", "src/c.js")
          (cpg.file.name.l :+ "none").foreach { f =>
              Seq("$app/stores", "$app/state", "./a", "fs", "none").foreach { s =>
                  m.importsModule(f, s) shouldBe m.imports.exists(i => i.file == f && i.module == s)
              }
          }
      }

      "find a call's file the same way through its method as through the file node" in {
          val cpg = fixture()
          cpg.call.size should be > 10
          cpg.call.foreach { c =>
              withClue(s"${c.code}: ") { c.file.name.headOption shouldBe Some(c.method.filename) }
          }
      }
  }
end JsModulesTest

/** The work behind the queries as a project grows. */
class JsModulesScalingTest extends DataFlowCodeToCpgSuite:

  private val Ratio = 2.2

  /** `n` files that import a mix of packages and make `m` calls each, one of the files without any
    * wanted import (`plain`), and a bundle of `k` calls importing a few packages.
    */
  private def counted(n: Int, m: Int, k: Int): (Map[String, Long], Int, Int) =
    val files = (0 until n).map { i =>
      val head = i % 3 match
        case 0 => "import axios from 'axios'; import { exec as run } from 'child_process';"
        case 1 =>
            "import DOMPurify from 'dompurify'; import fs from 'fs'; import { page } from '$app/stores';"
        case _ => "import { helper } from './util'; const ky = require('ky');"
      val body = (0 until m).map { j =>
          s"axios.get(a$j); run(c$j); DOMPurify.sanitize(h$j); fs.readFile(p$j); other.readFile(p$j); ky.get(u$j); helper($j); page.url.searchParams.get(q$j); other.get($j);"
      }.mkString("\n")
      s"$head\n$body\n" -> s"src/f$i.js"
    }
    val bundle =
        "import axios from 'axios'; import { exec as run } from 'child_process'; import DOMPurify from 'dompurify';\n" +
            (0 until k).map(j => s"axios.get(a$j); run(c$j); DOMPurify.sanitize(h$j); o.get($j);")
                .mkString("\n") -> "dist/bundle.js"
    val all  = files :+ bundle
    val cpg  = all.tail.foldLeft(code(all.head._1, all.head._2))((c, f) => c.moreCode(f._1, f._2))
    val mods = new JsModules(cpg)
    JsStats.reset()
    new JsFrameworkRecognizersPass(cpg).createAndApply()
    val keys = Seq(
      "compute.importFilter",
      "visit.importFilter",
      "compute.packageOf",
      "visit.importsOf",
      "compute.filesImporting",
      "visit.gate.client",
      "visit.gate.direct",
      "visit.gate.sanitizer",
      "visit.gate.serverRequest"
    ).map(k => k -> JsStats.get(k)).toMap
    (keys, mods.imports.size, mods.imports.map(i => (i.file, i.packageName)).distinct.size)
  end counted

  private lazy val small     = counted(6, 4, 20)
  private lazy val moreCalls = counted(6, 8, 40)
  private lazy val moreFiles = counted(12, 4, 20)

  "The import queries" should {

      "compute each import's package once, however many calls there are" in {
          small._1("compute.packageOf") should be > 0L
          small._1("compute.packageOf") should be <= small._2.toLong
          moreCalls._1("compute.packageOf") shouldBe small._1("compute.packageOf")
      }

      "filter a file's imports once per (file, package), not once per call" in {
          small._1("compute.importFilter") should be > 0L
          moreCalls._1("compute.importFilter") shouldBe small._1("compute.importFilter")
          moreCalls._1("visit.importFilter") shouldBe small._1("visit.importFilter")
          // the files that import a package list are found once per list
          small._1("compute.filesImporting") should be > 0L
          moreCalls._1("compute.filesImporting") shouldBe small._1("compute.filesImporting")
          // the filters run for pairs of a file and a package a recognizer wants
          small._1("compute.importFilter") should be <= (small._3 * 64).toLong
      }

      "read a file's import list a number of times that does not grow with its calls" in {
          moreCalls._1("visit.importsOf") shouldBe small._1("visit.importsOf")
          // the memoised queries never list a file's imports again: only a few sites do, once
          small._1("visit.importsOf") should be <= small._2.toLong
      }

      "grow with the number of files, not faster" in {
          Seq("compute.importFilter", "visit.importFilter", "compute.packageOf", "visit.importsOf")
              .foreach { k =>
                  withClue(s"$k: ") {
                      moreFiles._1(k).toDouble should be <= small._1(k) * Ratio
                  }
              }
      }

      "do per-call work only for calls in files that import the packages the recognizer wants" in {
          def gated(plainCalls: Int): Map[String, Long] =
            val importing = (0 until 5).map(j =>
                s"axios.get(a$j); axios(a$j); DOMPurify.sanitize(h$j); got.get(g$j);"
            )
                .mkString(
                  "import axios from 'axios'; import got from 'got'; import DOMPurify from 'dompurify';\n",
                  "\n",
                  ""
                )
            val plain = (0 until plainCalls).map(j =>
                s"api.get(a$j); axios(a$j); safe.sanitize(h$j); got.get($j);"
            )
                .mkString("\n")
            val cpg = code(importing, "src/imp.js").moreCode(plain, "src/plain.js")
            JsStats.reset()
            new JsFrameworkRecognizersPass(cpg).createAndApply()
            Seq(
              "visit.gate.client",
              "visit.gate.direct",
              "visit.gate.sanitizer",
              "visit.gate.serverRequest"
            ).map(k => k -> JsStats.get(k)).toMap
          end gated
          val few  = gated(5)
          val many = gated(50)
          // the 5 `axios.get` calls of the importing file pass the client gate, per pass that asks
          few("visit.gate.client") should be >= 5L
          few("visit.gate.sanitizer") should be >= 5L
          few("visit.gate.direct") should be >= 5L
          few("visit.gate.serverRequest") should be >= 5L
          // ten times the calls in the file that imports nothing change nothing
          many shouldBe few
      }
  }
end JsModulesScalingTest
