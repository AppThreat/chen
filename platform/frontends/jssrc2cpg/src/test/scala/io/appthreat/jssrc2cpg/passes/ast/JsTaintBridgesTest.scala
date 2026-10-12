package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.{Cpg, Operators}
import io.shiftleft.semanticcpg.language.*

/** What carries a JavaScript value where no call does: class fields read by another method, reactive
  * derivations, closures over a component's top-level variables, and member chains - the last two
  * in the def-use edges themselves.
  */
class JsTaintBridgesTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def show(paths: Iterator[Path]): List[String] =
      paths.map(_.elements.map(_.code).mkString(" -> ")).l

  "Def-use edges" should {
      "carry a value through a read of a read" in {
          val cpg = code(
            """
          |function a(e, route) {
          |  const el = document.getElementById('out');
          |  el.innerHTML = e.data.html;
          |  el.outerHTML = route.query.next;
          |}
          |""".stripMargin,
            "nested.js"
          )
          val sinks = cpg.call.nameExact(Operators.assignment).code("el\\.(inner|outer)HTML = .*")
          show(sinks.reachableByFlows(cpg.parameter.nameExact("e"))) should not be empty
          show(cpg.call.nameExact(Operators.assignment).code("el\\.outerHTML.*")
              .reachableByFlows(cpg.parameter.nameExact("route"))) should not be empty
      }

      "carry a captured variable to every read in the closure, not only the first" in {
          val cpg = code(
            """
          |export default function Go(params) {
          |  const next = params.get('next');
          |  function handle() {
          |    if (next) {
          |      window.location.href = next;
          |    }
          |  }
          |  return handle;
          |}
          |""".stripMargin,
            "go.js"
          )
          val sink = cpg.call.nameExact(Operators.assignment).code("window\\.location\\.href = next")
          show(sink.reachableByFlows(cpg.call.nameExact("get"))) should not be empty
      }
  }

  "The member bridge" should {
      "make a field assigned from a source a source where another method reads it" in {
          val cpg = tagged(code(
            """
          |import { Component, inject } from '@angular/core';
          |import { ActivatedRoute } from '@angular/router';
          |@Component({ selector: 'app-o', template: '' })
          |export class OComponent {
          |  private route = inject(ActivatedRoute);
          |  orderId: string;
          |  label = 'x';
          |  ngOnInit() {
          |    this.route.paramMap.subscribe(pm => { this.orderId = pm.get('id'); });
          |  }
          |  open() { window.open('/ftp/order_' + this.orderId + '.pdf'); window.open(this.label); }
          |}
          |""".stripMargin,
            "o.component.ts"
          ))
          cpg.tag.name("framework-input").call.code.l should contain("this.orderId")
          cpg.tag.name("framework-input").call.code.l should not contain "this.label"
      }
  }

  "The reactive bridge" should {
      "make a derived value a source, and a sanitising derivation a sanitiser" in {
          val cpg = tagged(code(
            """
          |import { computed } from 'vue';
          |import { useRoute } from 'vue-router';
          |import DOMPurify from 'dompurify';
          |const route = useRoute();
          |const id = computed(() => route.params.id);
          |const clean = computed(() => DOMPurify.sanitize(String(route.query.q)));
          |export function render(el) { el.innerHTML = id.value; el.outerHTML = clean.value; }
          |""".stripMargin,
            "view.js"
          ))
          cpg.tag.name("framework-input").identifier.name.l should contain("id")
          cpg.tag.name("sanitizer-xss").call.code.l.filter(_.startsWith("computed")) should not be empty
      }

      "stop at a sanitiser when looking for a source" in {
          val cpg = tagged(code(
            """
          |import { useParams } from 'react-router-dom';
          |export default function Order() {
          |  const { id } = useParams();
          |  const n = Number(id);
          |  function show(el) { el.innerHTML = '<b>' + n + '</b>'; }
          |  return <div onClick={show} />;
          |}
          |""".stripMargin,
            "order.jsx"
          ))
          cpg.tag.name("framework-input").identifier.name.l should not contain "n"
      }
  }
end JsTaintBridgesTest
