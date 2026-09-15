package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** Vue boundary semantics: the `createRouter` route table, the `defineProps`/`useRoute`
  * composition-API inputs, and the `v-html` template sink.
  */
class VueRouteTagsTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  "Vue route tables" should {

      "tag createRouter route records and their components" in {
          val cpg = tagged(code(
            """
          |import { createRouter, createWebHistory } from 'vue-router';
          |function Home() { return 'home'; }
          |function About() { return 'about'; }
          |
          |const routes = [
          |  { path: '/', component: Home },
          |  { path: '/about/:id', component: About }
          |];
          |const router = createRouter({ history: createWebHistory(), routes });
          |""".stripMargin,
            "router.js"
          ))

          cpg.literal.where(_.tag.name("framework-route")).code.sorted.l shouldBe List(
            "\"/\"",
            "\"/about/:id\""
          )
          // the routed components are entrypoints
          cpg.method.where(_.tag.name("framework-route")).name.sorted.l shouldBe
              List("About", "Home")
      }

      "not tag an object that merely has a path property" in {
          val cpg = tagged(code(
            """
          |import path from 'path';
          |const config = { path: '/tmp', label: 'temp' };
          |export default config;
          |""".stripMargin,
            "config.js"
          ))

          cpg.literal.where(_.tag.name("framework-route")).l shouldBe empty
      }

      "not tag a { path, children } file tree even when a router is imported" in {
          val cpg = tagged(code(
            """
          |import { createRouter } from 'vue-router';
          |const tree = { path: './src', children: [ { path: 'src/a.js', children: [] } ] };
          |""".stripMargin,
            "tree.js"
          ))

          // `children` is only a weak sibling key: it also describes trees and menus, so a record
          // carrying nothing else has to have a route-shaped path. Neither a relative filesystem
          // path nor a bare `src/a.js` qualifies.
          cpg.literal.where(_.tag.name("framework-route")).l shouldBe empty
      }

      "tag a nested parent route that has children and no component of its own" in {
          val cpg = tagged(code(
            """
          |import { createRouter } from 'vue-router';
          |function Users() { return 'users'; }
          |const routes = [
          |  { path: '/admin', children: [ { path: 'users', component: Users } ] }
          |];
          |""".stripMargin,
            "nested.js"
          ))

          // the parent qualifies on its route-shaped path, the child on its component
          cpg.literal.where(_.tag.name("framework-route")).code.sorted.l shouldBe List(
            "\"/admin\"",
            "\"users\""
          )
      }

      "tag a lazy route whose handler arrives through a dynamic import" in {
          val cpg = tagged(code(
            """
          |import { createRouter } from 'vue-router';
          |const routes = [
          |  { path: '/lazy', component: () => import('./Lazy.vue') },
          |  { path: 'reports', loadChildren: () => import('./reports') },
          |  { path: 'standalone', loadComponent: () => import('./one') }
          |];
          |""".stripMargin,
            "lazy.js"
          ))

          // loadChildren/loadComponent are strong keys, so a bare relative path is fine - there is
          // no identifier to resolve to a handler, but the route itself must not be lost
          cpg.literal.where(_.tag.name("framework-route")).code.sorted.l shouldBe List(
            "\"/lazy\"",
            "\"reports\"",
            "\"standalone\""
          )
      }

      "not tag a route table in a project with no router package" in {
          val cpg = tagged(code(
            """
          |const menu = [
          |  { path: '/home', component: renderHome },
          |  { path: '/about', redirect: '/home', pathMatch: 'full' }
          |];
          |function renderHome() { return 'home'; }
          |""".stripMargin,
            "menu.js"
          ))

          // the record shape matches, but no router package is imported
          cpg.literal.where(_.tag.name("framework-route")).l shouldBe empty
      }

      "not tag a filesystem-looking path value even in a routed project" in {
          val cpg = tagged(code(
            """
          |import { createRouter } from 'vue-router';
          |const routes = [
          |  { path: './relative', component: A },
          |  { path: '/ok', component: B }
          |];
          |function A() { return 1; }
          |function B() { return 2; }
          |""".stripMargin,
            "fsroute.js"
          ))

          cpg.literal.where(_.tag.name("framework-route")).code.l shouldBe List("\"/ok\"")
      }
  }

  "Vue composition API inputs" should {

      "tag defineProps as framework-input" in {
          val cpg = tagged(code(
            """<script setup>
          |import { defineProps } from 'vue';
          |const props = defineProps({ msg: String });
          |</script>
          |<template>
          |  <p>{{ props.msg }}</p>
          |</template>
          |""".stripMargin,
            "HelloVue.vue"
          ))

          cpg.tag.name("framework-input").call.name.l shouldBe List("defineProps")
      }

      "tag useRoute as framework-input and close a flow to a v-html render" in {
          val cpg = code(
            """<script setup>
          |import { useRoute } from 'vue-router';
          |const route = useRoute();
          |</script>
          |<template>
          |  <div v-html="route.params.slug"></div>
          |</template>
          |""".stripMargin,
            "PageVue.vue"
          )
          new ChennaiTagsPass(cpg).createAndApply()
          new EasyTagsPass(cpg).createAndApply()

          cpg.tag.name("framework-input").call.name.l shouldBe List("useRoute")
          val sources = cpg.tag.name("framework-input").call.nameExact("useRoute").l
          val sinks   = cpg.tag.name("framework-output").call.l
          sources should not be empty
          sinks should not be empty
          sinks.iterator.reachableByFlows(sources.iterator).size should be > 0
      }

      "close a flow from defineProps through a v-html render" in {
          val cpg = code(
            """<script setup>
          |import { defineProps } from 'vue';
          |const { content } = defineProps({ content: String });
          |</script>
          |<template>
          |  <div v-html="content"></div>
          |</template>
          |""".stripMargin,
            "ArticleVue.vue"
          )
          new ChennaiTagsPass(cpg).createAndApply()
          new EasyTagsPass(cpg).createAndApply()

          val sources = cpg.tag.name("framework-input").call.nameExact("defineProps").l
          val sinks   = cpg.tag.name("framework-output").call.l
          sources should not be empty
          sinks should not be empty
          sinks.iterator.reachableByFlows(sources.iterator).size should be > 0
      }

      "tag the props parameter of a setup method" in {
          val cpg = tagged(code(
            """
          |import { defineComponent } from 'vue';
          |export default defineComponent({
          |  setup(props) {
          |    return { greeting: props.msg };
          |  }
          |});
          |""".stripMargin,
            "OptionsApi.vue.js"
          ))

          cpg.tag.name("framework-input").parameter.name.l shouldBe List("props")
      }
  }

  "Nuxt server routes" should {

      "tag a defineEventHandler lambda as a route with input parameters" in {
          val cpg = tagged(code(
            """
          |import { defineEventHandler, readBody, getRouterParam } from 'h3';
          |
          |export default defineEventHandler(async (event) => {
          |  const body = await readBody(event);
          |  const id = getRouterParam(event, 'id');
          |  return { body, id };
          |});
          |""".stripMargin,
            "server/api/submit.post.ts"
          ))

          cpg.method.where(_.tag.name("framework-route")).name.l shouldBe List("anonymous")
          cpg.tag.name("framework-input").call.name.sorted.l shouldBe
              List("getRouterParam", "readBody")
      }
  }
end VueRouteTagsTest
