package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import PythonRecognizerUtil.*

/** B6 - cloud, queues and task frameworks.
  *
  * NB (Task 5 input): boto3 client objects are untyped at call sites (`s3.get_object(...)`), so the
  * service operations are matched by call NAME within the boto3-gated project; a receiver type join
  * (client -> service) would be more precise.
  */
object Boto3Recognizer extends PythonFrameworkRecognizer:

  override val name: String = "boto3"

  /** Reads/fetches: remote content entering the application. */
  private val IngressOps =
      Set(
        "get_object",
        "head_object",
        "list_objects",
        "list_objects_v2",
        "download_file",
        "download_fileobj",
        "select_object_content",
        "receive_message"
      )

  /** Writes/sends/enqueues: data leaving for a remote service. */
  private val EgressOps =
      Set(
        "put_object",
        "upload_file",
        "upload_fileobj",
        "copy_object",
        "delete_object",
        "invoke",
        "publish",
        "send_message",
        "send_batch",
        "put_item",
        "update_item",
        "delete_item"
      )

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, Set("boto3", "botocore"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    cpg.call.name(IngressOps.mkString("|")).foreach(c => tag(c, SERVICE_INGRESS_TAG))
    cpg.call.name(EgressOps.mkString("|")).foreach(c => tag(c, SERVICE_EGRESS_TAG))
end Boto3Recognizer

/** B6 - AWS Lambda event handlers: `def lambda_handler(event, context)` (also `handler` and
  * `*_handler` naming). The `event` parameter is attacker-controlled; `context` is not.
  *
  * The gate is a method-name index lookup (lambda projects have no importable framework); the
  * handler-shape check (first user parameter named `event`) keeps the run phase precise.
  */
object LambdaHandlerRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "aws-lambda"

  override def applies(cpg: Cpg): Boolean =
      cpg.method.nameExact("lambda_handler").nonEmpty ||
          cpg.method.nameExact("handler").nonEmpty ||
          cpg.method.nameExact("event_handler").nonEmpty

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    cpg.method
        .name(".*handler")
        .filterNot(_.isExternal)
        .filter(isUserMethod)
        .filter { m =>
            m.parameter.l.filterNot(p => SELF_NAMES.contains(p.name)).headOption
                .exists(_.name == "event")
        }
        .foreach { handler =>
          tag(handler, ROUTE_TAG)
          // Only the event payload is attacker-controlled; `context` carries runtime metadata.
          handler.parameter.l
              .filterNot(p => SELF_NAMES.contains(p.name))
              .headOption
              .foreach(p => tag(p, INPUT_TAG))
        }
end LambdaHandlerRecognizer

/** B6 - Azure Functions (v2 programming model: `@app.route`, `@app.timer_trigger`, ... on
  * `function_app.py` handlers, and the v1 `def main(req)` convention).
  */
object AzureFunctionsRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "azure-functions"

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, Set("azure"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    cpg.annotation.l
        .filter(a => a.name.toLowerCase.contains("trigger") || lastSegment(a.name) == "route")
        .flatMap(_.inAst.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Method])
        .filter(isUserMethod)
        .foreach(m => tagHandler(m))

    cpg.method.internal
        .nameExact("main")
        .filter(isUserMethod)
        .filter { m =>
            m.parameter.l.filterNot(p => SELF_NAMES.contains(p.name)).headOption
                .exists(p => p.name == "req" || p.name == "request")
        }
        .foreach(m => tagHandler(m))
end AzureFunctionsRecognizer

/** B6 - GCP Cloud Functions via `functions_framework` (`@functions_framework.http`, legacy `def
  * main(request)` entry points).
  */
object GcpCloudFunctionRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "gcp-functions"

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, Set("functions_framework"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    cpg.annotation.l
        .filter(a =>
            Set("http", "trigger", "entrypoint").contains(lastSegment(a.name.toLowerCase)) ||
                a.name.toLowerCase.contains("functions_framework")
        )
        .flatMap(_.inAst.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Method])
        .filter(isUserMethod)
        .foreach(m => tagHandler(m))

/** B6 - task queues and schedulers. Task functions are entry points: Celery `@app.task` /
  * `@shared_task`, RQ `@job`, Dramatiq `@dramatiq.actor`, APScheduler `@scheduled_job`. Enqueue
  * calls (`delay`, `apply_async`, `enqueue`, `send`) are service egress; APScheduler's `add_job`
  * registrations are cron metadata.
  */
object TaskQueueRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "task-queues"

  private val TaskDecorators =
      Set("task", "shared_task", "job", "actor", "scheduled_job", "periodic_task")

  private val EnqueueCalls = Set("delay", "apply_async", "enqueue")

  override def applies(cpg: Cpg): Boolean =
      importsAnyOf(cpg, Set("celery", "rq", "dramatiq", "apscheduler"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff

    cpg.annotation.l
        .filter(a => TaskDecorators.contains(lastSegment(a.name.toLowerCase)))
        .flatMap(_.inAst.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Method])
        .filter(isUserMethod)
        .foreach(m => tagHandler(m))

    cpg.call.name(EnqueueCalls.mkString("|")).foreach { c =>
        if !c.methodFullName.startsWith("<operator") then tag(c, SERVICE_EGRESS_TAG)
    }

    cpg.call.nameExact("add_job").foreach(c => tag(c, CRON_TAG))
end TaskQueueRecognizer

/** B6 - ORMs / database drivers. `execute`/`raw`/`extra`/`text` are already tagged `sql` by
  * EasyTagsPass (P1.3); this recognizer adds the shapes those rules miss: SQLAlchemy 2.0's
  * `select(...)` expression API and the asyncpg/psycopg fetch family.
  */
object OrmRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "orm-db"

  private val AsyncFetchCalls = Set("fetch", "fetchrow", "fetchval", "fetchmany", "fetchall")

  override def applies(cpg: Cpg): Boolean =
      importsAnyOf(cpg, Set("sqlalchemy", "asyncpg", "psycopg", "psycopg2"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    val roots              = importedRoots(cpg)
    if roots.contains("sqlalchemy") then
      cpg.call.nameExact("select").foreach { c =>
          if !c.methodFullName.startsWith("<operator") then tag(c, SQL_TAG)
      }
    if roots.exists(r => Set("asyncpg", "psycopg", "psycopg2").contains(r)) then
      cpg.call.name(AsyncFetchCalls.mkString("|")).foreach { c =>
          if !c.methodFullName.startsWith("<operator") then tag(c, SQL_TAG)
      }
end OrmRecognizer
