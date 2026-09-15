package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** Angular boundary semantics: decorator-declared inputs/outputs, the `Routes` config array, and
  * `ActivatedRoute` parameter reads.
  */
class AngularTagsTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  "Angular decorators" should {

      "tag @Input members and their this-reads as framework-input" in {
          val cpg = tagged(code(
            """
          |import { Component, Input } from '@angular/core';
          |@Component({ selector: 'app-hero' })
          |export class HeroComponent {
          |  @Input() hero: string;
          |  title = 'x';
          |  greet() { return this.hero; }
          |}
          |""".stripMargin,
            "hero.component.ts"
          ))

          cpg.tag.name("framework-input").member.name.l shouldBe List("hero")
          cpg.tag.name("framework-input").call.code.l shouldBe List("this.hero")
          // a plain member is not an input
          cpg.tag.name("framework-input").member.name.l should not contain "title"
      }

      "not bleed an @Input member onto similarly-named members" in {
          val cpg = tagged(code(
            """
          |import { Component, Input } from '@angular/core';
          |@Component({ selector: 'app-card' })
          |export class Card {
          |  @Input() id: string;
          |  idx: string;
          |  render() { return this.idx + this.id; }
          |}
          |""".stripMargin,
            "card.component.ts"
          ))

          // this.idx is NOT an @Input read, and the enclosing + call is not a field access
          cpg.tag.name("framework-input").call.code.l shouldBe List("this.id")
      }

      "tag @Output members as framework-output" in {
          val cpg = tagged(code(
            """
          |import { Component, Output, EventEmitter } from '@angular/core';
          |@Component({ selector: 'app-save' })
          |export class SaveComponent {
          |  @Output() saved = new EventEmitter<string>();
          |  save() { this.saved.emit('ok'); }
          |}
          |""".stripMargin,
            "save.component.ts"
          ))

          cpg.tag.name("framework-output").member.name.l shouldBe List("saved")
      }

      "tag DomSanitizer bypass calls as framework-output" in {
          val cpg = tagged(code(
            """
          |import { DomSanitizer } from '@angular/platform-browser';
          |export class SafeComponent {
          |  constructor(private sanitizer: DomSanitizer) {}
          |  trust(html: string) { return this.sanitizer.bypassSecurityTrustHtml(html); }
          |}
          |""".stripMargin,
            "safe.component.ts"
          ))

          cpg.tag.name("framework-output").call
              .name(".*bypassSecurityTrust.*").l should not be empty
      }
  }

  "Angular route tables" should {

      "tag the Routes array of a routing module" in {
          val cpg = tagged(code(
            """
          |import { NgModule } from '@angular/core';
          |import { RouterModule, Routes } from '@angular/router';
          |import { HeroComponent } from './hero.component';
          |
          |const routes: Routes = [
          |  { path: 'hero/:id', component: HeroComponent },
          |  { path: '', redirectTo: 'home', pathMatch: 'full' }
          |];
          |
          |@NgModule({ imports: [RouterModule.forRoot(routes)] })
          |export class AppModule {}
          |""".stripMargin,
            "app-routing.module.ts"
          ))

          cpg.literal.where(_.tag.name("framework-route")).code.sorted.l shouldBe List(
            "\"\"",
            "\"hero/:id\""
          )
      }

      "tag provideRouter route records" in {
          val cpg = tagged(code(
            """
          |import { provideRouter } from '@angular/router';
          |export const routes = [
          |  { path: 'detail/:id', component: DetailComponent }
          |];
          |export const appConfig = { providers: [provideRouter(routes)] };
          |""".stripMargin,
            "app.config.ts"
          ))

          cpg.literal.where(_.tag.name("framework-route")).code.l shouldBe List("\"detail/:id\"")
      }
  }

  "ActivatedRoute" should {

      "tag activatedRoute reads, not only a field literally named route" in {
          val cpg = tagged(code(
            """
          |import { Component } from '@angular/core';
          |import { ActivatedRoute } from '@angular/router';
          |@Component({ selector: 'app-detail' })
          |export class DetailComponent {
          |  constructor(private activatedRoute: ActivatedRoute) {}
          |  load() {
          |    return this.activatedRoute.snapshot.queryParams;
          |  }
          |}
          |""".stripMargin,
            "detail2.component.ts"
          ))

          val taggedCalls = cpg.tag.name("framework-input").call.code.l
          taggedCalls should contain("this.activatedRoute.snapshot.queryParams")
      }

      "tag route parameter reads as framework-input" in {
          val cpg = tagged(code(
            """
          |import { Component } from '@angular/core';
          |import { ActivatedRoute } from '@angular/router';
          |@Component({ selector: 'app-detail' })
          |export class DetailComponent {
          |  constructor(private route: ActivatedRoute) {}
          |  load() {
          |    const id = this.route.snapshot.params['id'];
          |    const q = this.route.queryParams;
          |    return id + q;
          |  }
          |}
          |""".stripMargin,
            "detail.component.ts"
          ))

          val taggedCalls = cpg.tag.name("framework-input").call.code.l
          (taggedCalls should contain).allOf("this.route.snapshot.params", "this.route.queryParams")
      }
  }
end AngularTagsTest
