package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** NestJS boundary semantics: a `@Controller` class's verb-decorated methods are the endpoints
  * (their parameters web-facing input, their `return` the response), the constructor-injected
  * service is called through `this.<field>`, and the ORM/jwt/hash calls the handlers reach are
  * sinks. The fixtures follow the shapes of nestjs-realworld-example-app and
  * node-express-realworld-example-app.
  */
class NestJsControllerTagsTest extends DataFlowCodeToCpgSuite:
  given io.shiftleft.semanticcpg.language.NoResolve.type =
      io.shiftleft.semanticcpg.language.NoResolve

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private val controller = """
    |import { Controller, Get, Post, Put, Body, Param, Query } from '@nestjs/common';
    |
    |@Controller('articles')
    |export class ArticleController {
    |  constructor(private readonly articleService: ArticleService) {}
    |
    |  @Get()
    |  async findAll(@Query() query) {
    |    return await this.articleService.findAll(query);
    |  }
    |
    |  @Post()
    |  async create(@Body('article') articleData) {
    |    return this.articleService.create(articleData);
    |  }
    |
    |  @Put(':slug')
    |  async update(@Param() params, @Body('article') articleData) {
    |    return await this.articleService.update(params.slug, articleData);
    |  }
    |
    |  async notARoute(unrelated) {
    |    return this.articleService.findAll(unrelated);
    |  }
    |}
    |""".stripMargin

  private val service = """
    |import { getRepository } from 'typeorm';
    |import * as jwt from 'jsonwebtoken';
    |import * as argon2 from 'argon2';
    |
    |export class ArticleService {
    |  constructor(private readonly articleRepository) {}
    |
    |  async findAll(query) {
    |    const qb = await getRepository(Article).createQueryBuilder('article');
    |    qb.where('article.author = :a', { a: query.author });
    |    return qb.getMany();
    |  }
    |
    |  async create(articleData) {
    |    await argon2.hash(articleData.password);
    |    return jwt.sign({ title: articleData.title }, 'secret');
    |  }
    |
    |  async update(slug, articleData) {
    |    return this.articleRepository.save(articleData);
    |  }
    |}
    |""".stripMargin

  "NestJS decorated controllers" should {

      "tag verb-decorated methods as routes and their parameters as web input" in {
          val cpg = tagged(code(controller, "article.controller.ts"))

          cpg.method.name("findAll|create|update").where(_.tag.name("framework-route")).name.sorted.l shouldBe
              List("create", "findAll", "update")
          cpg.method.name("notARoute").where(_.tag.name("framework-route")).l shouldBe empty

          // every parameter of a verb-decorated handler is web-facing, decorated or not
          cpg.method.name("update").parameter.where(_.tag.name("framework-input")).name.sorted.l shouldBe
              List("articleData", "params")
      }

      "ignore same-named decorators that do not come from @nestjs/common" in {
          val cpg = tagged(code(
            """
            |import { Controller } from '@nestjs/common';
            |import { Get, Body } from './my-decorators';
            |@Controller()
            |export class Other {
            |  @Get()
            |  async list(@Body() filter) {
            |    return filter;
            |  }
            |}
            |""".stripMargin,
            "other.ts"
          ))

          cpg.method.name("list").where(_.tag.name("framework-route")).l shouldBe empty
          cpg.method.name("list").parameter.where(_.tag.name("framework-input")).l shouldBe empty
      }

      "tag a request-data-decorated parameter on an otherwise undecorated method" in {
          val cpg = tagged(code(
            """
            |import { Headers } from '@nestjs/common';
            |export class Util {
            |  async track(@Headers() headers) {
            |    return headers['x-track'];
            |  }
            |}
            |""".stripMargin,
            "util.ts"
          ))

          cpg.method.name("track").parameter.where(_.tag.name("framework-input")).name.l shouldBe
              List("headers")
      }

      "resolve a constructor-injected service call to the internal method" in {
          val cpg = tagged(code(controller, "article.controller.ts").moreCode(
            service,
            "article.service.ts"
          ))

          val call = cpg.call.nameExact("findAll").where(
            _.method.fullName(".*ArticleController:findAll$")
          ).l
          inside(call) { case List(c) =>
              // the internal method, not a stub named after the recovered type
              c.callee.map(_.fullName).l shouldBe List(
                "article.service.ts::program:ArticleService:findAll"
              )
          }
      }

      "tag the ORM, jwt and hashing calls the handlers reach" in {
          val cpg = tagged(code(controller, "article.controller.ts").moreCode(
            service,
            "article.service.ts"
          ))

          cpg.call.nameExact("save").where(_.tag.name("framework-output")).code.l shouldBe List(
            "this.articleRepository.save(articleData)"
          )
          // a call whose first argument is a constant - the query-builder alias - binds its
          // values and is no sink, as for a constant SQL text
          cpg.call.nameExact("createQueryBuilder").where(_.tag.name("framework-output")).l shouldBe empty
          cpg.call.nameExact("hash").where(_.tag.name("library-call")).code.l shouldBe List(
            "argon2.hash(articleData.password)"
          )
          cpg.call.nameExact("sign").where(_.tag.name("library-call")).code.l shouldBe List(
            "jwt.sign({ title: articleData.title }, 'secret')"
          )
      }

      "resolve to the internal method also when a second file declares the same class" in {
          val cpg = tagged(code(controller, "article.controller.ts")
              .moreCode(service, "article.service.ts")
              .moreCode(service, "copy/article.service.ts"))

          // the hint is ambiguous between the two copies, so the type-hint linker itself does not
          // pick one; name-based call linking (the generic dynamic-call fallback) still applies
          val call = cpg.call.nameExact("findAll").where(
            _.method.fullName(".*ArticleController:findAll$")
          ).l
          inside(call) { case List(c) =>
              c.callee.map(_.fullName).l shouldBe List(
                "article.service.ts::program:ArticleService:findAll",
                "copy/article.service.ts::program:ArticleService:findAll"
              )
          }
      }
  }
end NestJsControllerTagsTest
