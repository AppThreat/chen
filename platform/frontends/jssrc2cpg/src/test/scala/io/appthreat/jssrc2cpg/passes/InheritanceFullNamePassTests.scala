package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*
import scala.annotation.nowarn

@nowarn // otherwise scalac warns about interpolated expressions
class InheritanceFullNamePassTests extends DataFlowCodeToCpgSuite:

  "inherited type full names" should {
      lazy val cpg = code(
        """
        |import Musician from "./domain/music";
        |
        |class MusicWithLyrics extends Musician {
        |  constructor(name, song, lyrics) {
        |    super(name, song);
        |    this.lyrics = lyrics;
        |  }
        |}
        |
        |const myMusician = new Musician('Rafi', 'song1');
        |const myMusicWithLyrics = new MusicWithLyrics('Fido', 'song1', 'lyrics');
        |""".stripMargin,
        "inheritance.js"
      ).moreCode(
        """
        |class Musician {
        |    constructor(name, song) {
        |        this.username = name;
        |        this.song = song;
        |    }
        |    sing() {
        |        console.log(`${this.username} says ${this.song}`);
        |    }
        |}
        |
        |export default Musician;
        |""".stripMargin,
        Seq("domain", "music.js").mkString("/")
      )

      "resolve the type being inherited fully" in {
          val List(tgtType) = cpg.typeDecl.nameExact("MusicWithLyrics").l
          tgtType.fullName shouldBe "inheritance.js::program:MusicWithLyrics"
          cpg.typeDecl("Musician").fullName.headOption shouldBe Some(
            Seq("domain", "music.js::program:Musician").mkString("/")
          )

          tgtType.inheritsFromTypeFullName.headOption shouldBe Some(
            Seq("domain", "music.js::program:Musician").mkString("/")
          )
      }

      "identifiers instantiated from these types should have their fully resolved types" in {
          val List(musician)           = cpg.identifier.nameExact("myMusician").l
          val List(musicianWithLyrics) = cpg.identifier.nameExact("myMusicWithLyrics").l
          musician.typeFullName shouldBe Seq("domain", "music.js::program:Musician").mkString("/")
          musicianWithLyrics.typeFullName shouldBe "inheritance.js::program:MusicWithLyrics"
      }
  }

  "inherited external types" should {
      lazy val cpg = code(
        """
        |import Musician from "music";
        |
        |class MusicWithLyrics extends Musician {
        |  constructor(name, song, lyrics) {
        |    super(name, song);
        |    this.lyrics = lyrics;
        |  }
        |}
        |""".stripMargin,
        "inheritance.js"
      )

      "resolve the type to a type stub from an external module" in {
          val List(tgtType) = cpg.typeDecl.nameExact("MusicWithLyrics").l
          tgtType.fullName shouldBe "inheritance.js::program:MusicWithLyrics"
          tgtType.inheritsFromTypeFullName.headOption shouldBe Some("music.js::program:Musician")
      }

  }

  "a base class bound by the class's file" should {
      lazy val cpg = code(
        """
        |import { Component } from "react";
        |import { Base } from "./base";
        |
        |class Local {}
        |export class Widget extends Component {}
        |export class Derived extends Base {}
        |export class Near extends Local {}
        |""".stripMargin,
        "widget.js"
      ).moreCode(
        """
        |export class Component {}
        |export class Base {}
        |""".stripMargin,
        "base.js"
      )

      "be the package's type when imported from a package, not a project class of its name" in {
          cpg.typeDecl.nameExact("Widget").inheritsFromTypeFullName.l should not contain
              "base.js::program:Component"
      }

      "be the class of the project file a relative import names" in {
          cpg.typeDecl.nameExact("Derived").inheritsFromTypeFullName.l shouldBe
              List("base.js::program:Base")
      }

      "be the class of the same file" in {
          cpg.typeDecl.nameExact("Near").inheritsFromTypeFullName.l shouldBe
              List("widget.js::program:Local")
      }

      "stay as it is when the pass runs again" in {
          val before = cpg.typeDecl.map(t => t.fullName -> t.inheritsFromTypeFullName.l).l.toMap
          new JavaScriptInheritanceNamePass(cpg).createAndApply()
          cpg.typeDecl.map(t => t.fullName -> t.inheritsFromTypeFullName.l).l.toMap shouldBe before
      }
  }
end InheritanceFullNamePassTests
