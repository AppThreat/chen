package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.Config
import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** Angular boundary semantics: decorator-declared inputs/outputs, signal inputs, the `Routes`
  * config array, and `ActivatedRoute` parameter reads.
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

      "not tag @Output members as sinks" in {
          // An emitted value goes to the parent component, not out of the application. Tagged as
          // framework-output, every @Input read that reached an emit became a "flow".
          val cpg = tagged(code(
            """
          |import { Component, Input, Output, EventEmitter } from '@angular/core';
          |@Component({ selector: 'app-save' })
          |export class SaveComponent {
          |  @Input() draft = '';
          |  @Output() saved = new EventEmitter<string>();
          |  save() { this.saved.emit(this.draft); }
          |}
          |""".stripMargin,
            "save.component.ts"
          ))

          cpg.tag.name("framework-output").member.name.l shouldBe empty
          cpg.tag.name("framework-output").call.code.l shouldBe empty
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

  "Angular signal inputs" should {

      "tag input() and input.required() members and their reads as framework-input" in {
          val cpg = tagged(code(
            """
          |import { Component, input, signal } from '@angular/core';
          |@Component({ selector: 'app-bio' })
          |export class BioComponent {
          |  bio = input<string>('');
          |  name = input.required<string>();
          |  count = signal(0);
          |  greet() { return this.bio() + this.name() + this.count(); }
          |}
          |""".stripMargin,
            "bio.component.ts"
          ))

          // count is component state, not an input, although it is read the same way
          cpg.tag.name("framework-input").member.name.l.sorted shouldBe List("bio", "name")
          cpg.tag.name("framework-input").call.code.l.sorted shouldBe List("this.bio", "this.name")
      }

      "close a flow from a signal input read to a sanitizer bypass" in {
          val cpg = tagged(code(
            """
          |import { Component, input } from '@angular/core';
          |import { DomSanitizer } from '@angular/platform-browser';
          |@Component({ selector: 'app-bio' })
          |export class BioComponent {
          |  bio = input<string>('');
          |  constructor(private sanitizer: DomSanitizer) {}
          |  html() {
          |    const raw = this.bio();
          |    return this.sanitizer.bypassSecurityTrustHtml(raw);
          |  }
          |}
          |""".stripMargin,
            "bio.component.ts"
          ))

          val sources = cpg.tag.name("framework-input").call.codeExact("this.bio").l
          val sinks   = cpg.tag.name("framework-output").call.l
          sources should not be empty
          sinks should not be empty
          sinks.iterator.reachableByFlows(sources.iterator).size should be > 0
      }

      "not tag a member initialised by an input function that is not Angular's" in {
          val cpg = tagged(code(
            """
          |import { Component } from '@angular/core';
          |import { input } from './prompt';
          |@Component({ selector: 'app-local' })
          |export class LocalComponent {
          |  bio = input('');
          |  read() { return this.bio(); }
          |}
          |""".stripMargin,
            "local.component.ts"
          ).moreCode(
            """
          |export function input(initial: string): () => string {
          |  return () => initial;
          |}
          |""".stripMargin,
            "prompt.ts"
          ).moreCode(
            """
          |import { Component, input } from '@angular/core';
          |import { forms } from './forms';
          |@Component({ selector: 'app-name' })
          |export class NameComponent {
          |  name = input('');
          |  box = forms.input('');
          |  rule = forms.required();
          |}
          |""".stripMargin,
            "name.component.ts"
          ))

          cpg.call.codeExact("this.bio()").size shouldBe 1
          cpg.tag.name("framework-input").member.name.l shouldBe List("name")
          cpg.tag.name("framework-input").call.code.l shouldBe empty
      }

      "tag an input.required() member when the types of @angular/core resolve" in {
          val cpg = tagged(code(
            """
          |import { Component, input } from '@angular/core';
          |@Component({ selector: 'app-name' })
          |export class NameComponent {
          |  name = input.required<string>();
          |  greet() { return this.name(); }
          |}
          |""".stripMargin,
            "name.component.ts"
          ).moreCode(
            """
          |export interface InputSignal<T> {
          |  (): T;
          |}
          |export declare const input: {
          |  <T>(initialValue?: T): InputSignal<T>;
          |  required<T>(): InputSignal<T>;
          |};
          |export declare function Component(metadata: unknown): ClassDecorator;
          |""".stripMargin,
            "node_modules/@angular/core/index.d.ts"
          ).withConfig(Config(tsTypes = true)))

          cpg.identifier.typeFullName.filter(_.contains("InputSignal")).l should not be empty
          cpg.tag.name("framework-input").member.name.l shouldBe List("name")
          cpg.tag.name("framework-input").call.code.l shouldBe List("this.name")
      }

      "tag an input() member in a class that has a method called input" in {
          val cpg = tagged(code(
            """
          |import { Component, input } from '@angular/core';
          |@Component({ selector: 'app-field' })
          |export class FieldComponent {
          |  label = input('');
          |  input(value: string) { return this.label() + value; }
          |}
          |""".stripMargin,
            "field.component.ts"
          ))

          cpg.tag.name("framework-input").member.name.l shouldBe List("label")
          cpg.tag.name("framework-input").call.code.l shouldBe List("this.label")
      }

      "tag signal inputs declared through a renamed import" in {
          val cpg = tagged(code(
            """
          |import { Component, input as field } from '@angular/core';
          |@Component({ selector: 'app-bio' })
          |export class BioComponent {
          |  bio = field<string>('');
          |  name = field.required<string>();
          |  greet() { return this.bio() + this.name(); }
          |}
          |""".stripMargin,
            "bio.component.ts"
          ))

          cpg.tag.name("framework-input").member.name.l.sorted shouldBe List("bio", "name")
          cpg.tag.name("framework-input").call.code.l.sorted shouldBe List("this.bio", "this.name")
      }

      "not tag a member that shares its name with a local variable initialised by input()" in {
          val cpg = tagged(code(
            """
          |import { Component, input } from '@angular/core';
          |@Component({ selector: 'app-local' })
          |export class LocalComponent {
          |  bio = input('');
          |  label = 'x';
          |  other = 'y';
          |  run(input: (value: string) => string) {
          |    const label = input('z');
          |    return label + this.label + this.bio();
          |  }
          |  build() {
          |    const other = input('');
          |    return other() + this.other;
          |  }
          |}
          |""".stripMargin,
            "local.component.ts"
          ))

          // the read, and the write of the field initialiser
          cpg.call.codeExact("this.label").size shouldBe 2
          cpg.call.codeExact("this.other").size shouldBe 2
          cpg.tag.name("framework-input").member.name.l shouldBe List("bio")
          cpg.tag.name("framework-input").call.code.l shouldBe List("this.bio")
      }

      "not tag a member assigned from input() in the constructor body" in {
          val cpg = tagged(code(
            """
          |import { Component, input } from '@angular/core';
          |import type { InputSignal } from '@angular/core';
          |@Component({ selector: 'app-late' })
          |export class LateComponent {
          |  bio = input('');
          |  late: InputSignal<string>;
          |  later: InputSignal<string>;
          |  constructor() {
          |    this.late = input('')
          |    this.later = input('');
          |  }
          |  read() { return this.late() + this.later() + this.bio(); }
          |}
          |""".stripMargin,
            "late.component.ts"
          ))

          cpg.call.codeExact("this.late()").size shouldBe 1
          cpg.call.codeExact("this.later()").size shouldBe 1
          cpg.tag.name("framework-input").member.name.l shouldBe List("bio")
          cpg.tag.name("framework-input").call.code.l shouldBe List("this.bio")
      }

      "not tag a member that shares its name with the condition of a conditional initialiser" in {
          val cpg = tagged(code(
            """
          |import { Component, input, signal } from '@angular/core';
          |declare const wide: boolean;
          |@Component({ selector: 'app-size' })
          |export class SizeComponent {
          |  wide = signal(false);
          |  size = wide ? input(1) : input(2);
          |  isWide() { return this.wide(); }
          |}
          |""".stripMargin,
            "size.component.ts"
          ))

          cpg.call.codeExact("this.wide()").size shouldBe 1
          cpg.tag.name("framework-input").member.name.l shouldBe empty
          cpg.tag.name("framework-input").call.code.l shouldBe empty
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
