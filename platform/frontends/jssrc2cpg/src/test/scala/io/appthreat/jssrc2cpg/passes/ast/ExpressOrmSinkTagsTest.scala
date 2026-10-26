package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** The response, ORM and credential sinks an express-style handler reaches, in the shapes of
  * node-express-realworld-example-app and express-drizzle-starter: `res.json(x)` as the response
  * body, Prisma model calls and TypeORM repository calls as database access, and `jwt.sign` /
  * `bcrypt` / `argon2` as credential handling.
  */
class ExpressOrmSinkTagsTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  "express response methods" should {

      "tag res.json(x) as a response sink, like send" in {
          val cpg = tagged(code(
            """
            |router.post('/users/login', async (req, res) => {
            |  const user = await login(req.body.user);
            |  res.json({ user });
            |  res.status(201).json({ user });
            |  res.sendStatus(204);
            |});
            |""".stripMargin,
            "auth.controller.ts"
          ))

          cpg.call.nameExact("json").where(_.tag.name("framework-output")).code.l shouldBe List(
            "res.json({ user })",
            "res.status(201).json({ user })"
          )
      }

      "keep a zero-argument res.json() as no output (the Fetch API read)" in {
          val cpg = tagged(code(
            """
            |async function f(res) {
            |  const body = await res.json();
            |  return body;
            |}
            |""".stripMargin,
            "fetch.ts"
          ))

          cpg.call.nameExact("json").where(_.tag.name("framework-output")).l shouldBe empty
      }
  }

  "ORM calls" should {

      "tag Prisma model calls as database access" in {
          val cpg = tagged(code(
            """
            |import prisma from '../../../prisma/prisma-client';
            |export async function createUser(email, username) {
            |  return await prisma.user.create({
            |    data: { username, email }
            |  });
            |}
            |export async function find(email) {
            |  return prisma.user.findUnique({ where: { email } });
            |}
            |""".stripMargin,
            "auth.service.ts"
          ))

          cpg.call.nameExact("create", "findUnique").where(_.tag.name("framework-output")).code.l
              .sorted shouldBe List(
            "prisma.user.create({\n    data: { username, email }\n  })",
            "prisma.user.findUnique({ where: { email } })"
          )
      }

      "tag TypeORM repository calls as database access" in {
          val cpg = tagged(code(
            """
            |import { getRepository } from 'typeorm';
            |export class ArticleService {
            |  constructor(private readonly userRepository) {}
            |  async findOne(author) {
            |    return this.userRepository.findOne({ username: author });
            |  }
            |  async build() {
            |    return getRepository(Article).createQueryBuilder('article');
            |  }
            |}
            |""".stripMargin,
            "article.service.ts"
          ))

          cpg.call.nameExact("findOne").where(_.tag.name("framework-output")).code.l shouldBe List(
            "this.userRepository.findOne({ username: author })"
          )
          // the builder call's first argument is the constant alias: it binds its
          // values, as a constant SQL text does, and is no sink
          cpg.call.nameExact("createQueryBuilder").where(_.tag.name("framework-output")).l shouldBe empty
      }

      "not tag a repository-suffixed name that is not a receiver" in {
          val cpg = tagged(code(
            """
            |export async function f(userRepository) {
            |  return userRepository.find();
            |}
            |""".stripMargin,
            "misc.ts"
          ))

          cpg.call.nameExact("find").where(_.tag.name("framework-output")).l shouldBe empty
      }
  }

  "credential calls" should {

      "tag jwt.sign, bcrypt and argon2 hashing as library calls" in {
          val cpg = tagged(code(
            """
            |import * as jwt from 'jsonwebtoken';
            |import * as bcrypt from 'bcryptjs';
            |import * as argon2 from 'argon2';
            |export function generateToken(id) {
            |  return jwt.sign({ user: { id } }, process.env.JWT_SECRET || 's', { expiresIn: '60d' });
            |}
            |export async function register(password) {
            |  const hashedPassword = await bcrypt.hash(password, 10);
            |  const ok = await bcrypt.compare(password, hashedPassword);
            |  return argon2.hash(password);
            |}
            |""".stripMargin,
            "auth.service.ts"
          ))

          cpg.call.name("sign", "hash", "compare").where(_.tag.name("library-call")).code.l
              .sorted shouldBe List(
            "argon2.hash(password)",
            "bcrypt.compare(password, hashedPassword)",
            "bcrypt.hash(password, 10)",
            "jwt.sign({ user: { id } }, process.env.JWT_SECRET || 's', { expiresIn: '60d' })"
          )
      }

      "follow the import, not the name: renamed bindings, require, and express-jwt's jwt" in {
          val cpg = tagged(code(
            """
            |import { sign as issue } from 'jsonwebtoken';
            |const crypt = require('bcrypt');
            |export function token(user) {
            |  return issue({ id: user.id }, 'k');
            |}
            |export async function store(password) {
            |  return crypt.hash(password, 10);
            |}
            |""".stripMargin,
            "auth.ts"
          ).moreCode(
            """
            |import jwt from 'express-jwt';
            |export const guard = (opts) => jwt.sign(opts);
            |""".stripMargin,
            "guard.ts"
          ))

          cpg.call.where(_.tag.name("library-call")).code.l.sorted shouldBe List(
            "crypt.hash(password, 10)",
            "issue({ id: user.id }, 'k')"
          )
      }

      "not tag an ordinary sign or hash call" in {
          val cpg = tagged(code(
            """
            |export function sign(data) {
            |  return sign2(data);
            |}
            |function hash(x) { return x; }
            |export const r = hash(sign('a'));
            |""".stripMargin,
            "misc.ts"
          ))

          cpg.call.name("sign", "hash").where(_.tag.name("library-call")).l shouldBe empty
      }
  }
end ExpressOrmSinkTagsTest
