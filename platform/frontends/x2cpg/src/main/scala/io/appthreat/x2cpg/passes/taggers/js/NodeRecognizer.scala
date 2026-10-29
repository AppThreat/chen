package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Node.js on the server side of a frontend project: the route handlers, server actions, loaders
  * and API endpoints of Next.js, Nuxt/Nitro, SvelteKit, Astro and Remix all run on Node, and reach
  * the same core modules and database clients.
  *
  * Sinks: commands (`child_process`), files (`fs`, `fs/promises`, `fs-extra`), code (`vm`, a
  * computed `require`), SQL strings (`pg`, `mysql2`, `better-sqlite3`, `sqlite3`, `knex.raw`,
  * `sequelize.query`, prisma's `$queryRawUnsafe`, db0's `exec`/`prepare`, `postgres`'s `unsafe`)
  * outgoing requests (`http.request`, `got`, `undici`, `node-fetch`), and credential handling
  * (`jsonwebtoken`'s `sign`, `bcrypt`/`bcryptjs`/`argon2` hashing). A tagged template (`` sql`...
  * ${x}` ``, `` db.sql`...` ``) binds its values as parameters and is no SQL sink. `path.basename`
  * keeps a file name inside its directory.
  *
  * Bindings are resolved through each file's imports and `require`s, including renames and
  * namespace imports (`import * as cp from 'node:child_process'`).
  */
object NodeRecognizer extends JsFrameworkRecognizer:

  val name: String = "node"

  private val CommandModule = "child_process"
  private val FileModules   = Seq("fs", "fs/promises", "fs-extra", "graceful-fs")
  private val CodeModule    = "vm"

  /** A token signed or a password hashed with request data: no injection, but the credential
    * handling a reviewer wants a flow to reach (jsonwebtoken and bcrypt each appear in three corpus
    * projects, argon2 in one).
    */
  private val TokenModule     = "jsonwebtoken"
  private val PasswordModules = Seq("bcrypt", "bcryptjs", "argon2")

  private val SqlPackages = Seq(
    "pg",
    "mysql",
    "mysql2",
    "better-sqlite3",
    "sqlite3",
    "@appthreat/sqlite3",
    // `node:sqlite` resolves to the package name `sqlite`, as the `sqlite` wrapper package does
    "sqlite",
    "knex",
    "sequelize",
    "@prisma/client",
    "drizzle-orm",
    "db0",
    "postgres",
    "@vercel/postgres",
    "@neondatabase/serverless",
    "@libsql/client",
    "@planetscale/database",
    "kysely",
    "typeorm",
    "mssql",
    "oracledb"
  )

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses(
        (Seq(CommandModule, CodeModule, "path", "http", "https", TokenModule) ++
            FileModules ++ PasswordModules ++ SqlPackages ++ ServerRequestPackages)*
      ) || NitroRecognizer.isNitroProject(ctx)

  private val CommandFunctions =
      Set("exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork")

  private val FileFunctions = Set(
    "readFile",
    "readFileSync",
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "createReadStream",
    "createWriteStream",
    "unlink",
    "unlinkSync",
    "rm",
    "rmSync",
    "rmdir",
    "readdir",
    "readdirSync",
    "open",
    "openSync",
    "copyFile",
    "copyFileSync",
    "rename",
    "renameSync",
    "mkdir",
    "mkdirSync",
    "readJson",
    "readJSON",
    "outputFile",
    "remove",
    "sendFile"
  )

  private val CodeFunctions =
      Set("runInNewContext", "runInThisContext", "runInContext", "compileFunction")

  private val SqlMethods = Set(
    "query",
    "execute",
    "prepare",
    "raw",
    "whereRaw",
    "orderByRaw",
    "havingRaw",
    "joinRaw",
    "$queryRawUnsafe",
    "$executeRawUnsafe",
    "unsafe"
  )

  /** Methods that run SQL given as their first argument on a handle known to be a database -
    * sqlite3 and its `@appthreat/sqlite3` fork (`run`, `get`, `all`, `each`, `map`, `exec`,
    * `iterate`, `stream`), better-sqlite3 and `node:sqlite` (`exec`, `pragma`), the `sqlite`
    * wrapper. Elsewhere these names mean something else: `re.exec(s)`, `map.get(k)`.
    */
  private val SqlHandleMethods =
      Set("exec", "run", "all", "get", "each", "map", "iterate", "stream", "pragma")

  /** What a database handle is usually called, for a handle created in another module (`export
    * const db = new Database(...)` in `lib/db.ts`) where its construction is out of reach.
    */
  private val HandleNames =
      "(?i)^(this\\.)?_?(db|database|sqlite|sqlitedb|conn|connection|pool|client)$"

  private val ServerRequestPackages =
      Seq("got", "undici", "node-fetch", "needle", "cross-fetch", "isomorphic-fetch")

  def run(ctx: JsContext): Unit =
    tagModuleCalls(ctx, Seq(CommandModule), CommandFunctions, Seq("shell-exec"))
    tagModuleCalls(ctx, FileModules, FileFunctions, Seq("file-io"))
    tagModuleCalls(ctx, Seq(CodeModule), CodeFunctions, CodeSink)
    tagModuleCalls(ctx, Seq(TokenModule), Set("sign"), Seq("library-call"))
    tagModuleCalls(ctx, PasswordModules, Set("hash", "compare", "verify"), Seq("library-call"))
    tagScriptConstructors(ctx)
    tagDynamicRequire(ctx)
    tagSql(ctx)
    tagServerRequests(ctx)
    tagPathSanitizers(ctx)

  /** Calls of `functions` exported by `modules`, by whichever binding the file has: a named import
    * (renamed or not), or a member of a default/namespace/require binding (`fs.readFile`,
    * `require('fs').readFile`, `fs.promises.readFile`).
    */
  private def tagModuleCalls(
    ctx: JsContext,
    modules: Seq[String],
    functions: Set[String],
    tags: Seq[String]
  ): Unit =
    val files = ctx.modules.filesImporting(modules*)
    if files.isEmpty then return
    // Locals bound to `promisify(...)`, so that only their calls and the named functions are
    // examined further.
    val promisifiedLocals = ctx.cpg.call.nameExact("promisify").l.flatMap { p =>
        p.inAssignment.argument(1).isIdentifier.name.l.map(n => (p.method.filename, n))
    }.toSet
    // `import { exec as run }`: `run(cmd)` is called by the name the file gave it
    val renamed = ctx.modules.namedBindings(modules, functions)
    val calls =
        ctx.cpg.call.filter(c =>
            functions.contains(callName(c)) || promisifiedLocals.contains((
              c.method.filename,
              c.name
            )) ||
                renamed.contains((c.method.filename, c.name))
        ).filter { c =>
          val file = c.method.filename
          files.contains(file) && moduleFunction(ctx, c, file, modules, functions)
        }
    // Only a computed argument can carry anything in; a constant command or path is no finding.
    ctx.tagger.tag(calls.filter(hasComputedArgument), tags*)
  end tagModuleCalls

  private[js] def moduleFunction(
    ctx: JsContext,
    c: Call,
    file: String,
    modules: Seq[String],
    functions: Set[String]
  ): Boolean =
    val name = callName(c)
    def namedFrom(local: String) =
        modules.exists(m => ctx.modules.namedLocalsOf(file, m).contains(local))
    promisified(ctx, c, file, modules, functions) || (
      c.receiver.headOption.flatMap(memberPath) match
        // `exec(cmd)` - a named import, possibly renamed: the local name is what is called
        case Some(List(local)) =>
            modules.exists(m =>
                functions.exists(f => ctx.modules.localNamesOf(file, m, f).contains(local))
            ) || functions.contains(name) &&
            modules.exists(m => ctx.modules.moduleBindingsOf(file, m).contains(local))
        // `cp.exec(cmd)`, `fs.promises.readFile(p)`
        case Some(path) if path.size >= 2 =>
            functions.contains(name) && (
              modules.exists(m => ctx.modules.moduleBindingsOf(file, m).contains(path.head)) ||
                  // `fsp.readFile` where `import { promises as fsp } from 'fs'`
                  namedFrom(path.head)
            )
        case _ =>
            // `require('child_process').exec(cmd)`
            functions.contains(name) && c.receiver.headOption.exists(r =>
                modules.exists(m =>
                    r.code.contains(s"require(\"$m\")") || r.code.contains(s"require('$m')")
                )
            )
    )
  end moduleFunction

  /** `const run = promisify(exec)`; `run(cmd)` is `exec(cmd)`. */
  private def promisified(
    ctx: JsContext,
    c: Call,
    file: String,
    modules: Seq[String],
    functions: Set[String]
  ): Boolean =
      c.receiver.headOption.exists {
          case id: Identifier =>
              JsValues.origin(id) match
                case p: Call if p.name == "promisify" =>
                    p.argument.filter(_.argumentIndex == 1).headOption.exists {
                        case fn: Identifier =>
                            modules.exists(m =>
                                functions.exists(f =>
                                    ctx.modules.localNamesOf(file, m, f).contains(fn.name)
                                )
                            )
                        case fa: Call => fieldName(fa).exists(functions.contains)
                        case _        => false
                    }
                case _ => false
          case _ => false
      }

  private def hasComputedArgument(c: Call): Boolean =
      c.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).headOption.exists {
          case _: Literal => false
          case _          => true
      }

  /** `new vm.Script(code)` */
  private def tagScriptConstructors(ctx: JsContext): Unit =
    val files = ctx.modules.filesImporting(CodeModule)
    if files.isEmpty then return
    val scripts = ctx.cpg.call.nameExact("<operator>.new", Operators.alloc)
        .filter(c => files.contains(c.method.filename))
        .filter(c => c.code.matches("(?s)new\\s+([\\w$]+\\.)?Script\\(.*"))
        .filter(hasComputedArgument)
    ctx.tagger.tag(scripts, CodeSink*)

  /** `require(name)` with a computed name loads and runs whatever module it names. */
  private def tagDynamicRequire(ctx: JsContext): Unit =
    val requires = ctx.cpg.call.nameExact("require").filter(c =>
        c.argument.filter(_.argumentIndex == 1).headOption.exists {
            case _: Literal => false
            case _          => true
        }
    )
    ctx.tagger.tag(requires, CodeSink*)

  /** True for a tagged template call (`` sql`...` ``), whose interpolations are bound parameters.
    */
  private def isTaggedTemplate(e: Expression): Boolean =
      e match
        case c: Call => JsShapes.isTaggedTemplateCall(c)
        case _       => false

  private def sqlArgument(c: Call): Option[Expression] =
      c.argument.filter(_.argumentIndex == 1).headOption

  private def isSqlString(e: Expression): Boolean =
      e match
        case _: Literal => false
        case _: Block   => false // `client.query({ query })` - a GraphQL or config object
        case other      => !isTaggedTemplate(other)

  private def tagSql(ctx: JsContext): Unit =
    val usesSql = ctx.modules.uses(SqlPackages*) || NitroRecognizer.isNitroProject(ctx)
    if !usesSql then return
    // Database handles: the result of `useDatabase()` (db0, Nitro), `new Database(...)`
    // (better-sqlite3, sqlite3), `open(...)` (sqlite), `createClient(...)` (libsql).
    def isDatabaseHandle(r: Expression): Boolean =
        (JsValues.origin(r) match
          // `new Database(f)` is lowered to a block around the `new` call
          case b: Block if b.code.trim.startsWith("new ") =>
              b.ast.isCall.nameExact("<operator>.new").headOption.getOrElse(b)
          case other => other
        ) match
          case fa: Call if fa.name == Operators.fieldAccess => fa.code.matches(HandleNames)
          case c: Call =>
              c.name == "useDatabase" || c.name == "createDatabase" || c.name == "createClient" ||
              // new Database(f), new sqlite3.Database(f), new sqlite3.verbose().Database(f),
              // new DatabaseSync(f) (node:sqlite, @appthreat/sqlite3/compat), new Pool(), new Client()
              c.code.matches(
                "(?s)(await\\s+)?new\\s+([\\w$]+(\\(\\))?\\.)*(Database|DatabaseSync|Pool|Client)\\(.*"
              ) ||
              (c.name == "open" && c.code.contains("driver"))
          case other => other.code.matches(HandleNames)
    val sqlCalls = ctx.cpg.call.filter { c =>
      val name = callName(c)
      (SqlMethods.contains(name) || SqlHandleMethods.contains(name)) &&
      receiverOf(c).exists(r =>
          r.code != "this" &&
              (SqlMethods.contains(name) || isDatabaseHandle(r)) &&
              // `knex.raw`, `prisma.$queryRawUnsafe`, `pool.query`, `db.exec` - never a DOM or
              // RegExp receiver
              !r.code.matches("(?s)^(document|window|this\\.document|/.*/[a-z]*)$")
      ) && !JsShapes.isTaggedTemplateCall(c) && sqlArgument(c).exists(isSqlString)
    }
    // drizzle `sql.raw(x)` / postgres `sql.unsafe(x)` are covered by name above.
    ctx.tagger.tag(sqlCalls, "sql")
  end tagSql

  /** Outgoing requests from server code: `got(url)`, `http.get(url)`, `request(url)` from undici.
    */
  private def tagServerRequests(ctx: JsContext): Unit =
    val requestPackages = ServerRequestPackages ++ Seq("http", "https")
    val directClients = ctx.cpg.call.filter { c =>
      val file = c.method.filename
      if !ctx.modules.importsAny(file, requestPackages) then false
      else
        JsStats.visited("gate.serverRequest")
        c.receiver.headOption.flatMap(memberPath) match
          case Some(List(local)) =>
              ServerRequestPackages.exists(p =>
                  ctx.modules.moduleBindingsOf(file, p).contains(local) ||
                      ctx.modules.localNamesOf(file, p, "request").contains(local) ||
                      ctx.modules.localNamesOf(file, p, "fetch").contains(local)
              )
          case Some(List(binding, method)) =>
              (Set("get", "post", "put", "patch", "delete", "head", "request", "stream").contains(
                method
              )) && (ServerRequestPackages ++ Seq("http", "https")).exists(p =>
                  ctx.modules.moduleBindingsOf(file, p).contains(binding)
              )
          case _ => false
    }.l
    ctx.tagger.tag(directClients.iterator, INGRESS)
    directClients.foreach(p => ctx.tagger.tag(JsValues.consumersOf(p).iterator, INGRESS))
    val requests = directClients.flatMap(c =>
        c.argument.filter(_.argumentIndex == 1).headOption.toList.flatMap(requestSinksFor(c, _))
    )
    ctx.tagger.tag(requests.iterator, (RequestSink :+ SSRF)*)
  end tagServerRequests

  /** `path.basename(p)` keeps a name inside the directory it is joined to. */
  private def tagPathSanitizers(ctx: JsContext): Unit =
    val members = ctx.cpg.call.nameExact("basename").filter { c =>
        ctx.modules.importsAny(c.method.filename, Seq("path")) && c.receiver.headOption.flatMap(
          memberPath
        ).exists {
            case List(binding, _) =>
                ctx.modules.moduleBindingsOf(c.method.filename, "path").contains(binding)
            case _ => false
        }
    }
    val named = ctx.modules.namedImportCalls(Seq("path"), Set("basename"))
    ctx.tagger.tag(members ++ named, SANITIZER, sanitizerFor("file-io"))
end NodeRecognizer
