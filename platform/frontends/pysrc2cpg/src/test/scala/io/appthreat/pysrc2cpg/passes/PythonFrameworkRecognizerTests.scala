package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.taggers.python.{PythonFrameworkRecognizersPass, PythonRecognizers}
import io.shiftleft.semanticcpg.language.*

/** Unit tests for the Task-4 framework recognizers: the `applies` gates (import-keyed and required
  * to say NO on projects that don't use a framework) and the structural tagging each recognizer
  * emits. Tags are asserted through the same `cpg.tag` traversals reachables uses.
  */
class PythonFrameworkRecognizerTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def withRecognizers(cpg: io.shiftleft.codepropertygraph.Cpg)(
    body: => Unit
  ): Unit =
    new PythonFrameworkRecognizersPass(cpg).createAndApply()
    body

  "every recognizer's applies gate returns false on a project that does not use it" in {
      val cpg = code("""import subprocess
            |def run_tool(tool_name):
            |    return subprocess.run(tool_name, shell=True)
            |def invoke_and_add_job(payload):
            |    return payload
            |class PlainThing:
            |    def get(self):
            |        return 1
            |""".stripMargin)

      val gatedIn = PythonRecognizers.all.filter(_.applies(cpg)).map(_.name)
      gatedIn shouldBe empty
  }

  "applies gates return true only for recognizers whose framework is imported" in {
      val cpg = code("""import flask
            |import boto3
            |import grpc
            |""".stripMargin)

      PythonRecognizers.all.filter(_.applies(cpg)).map(_.name).sorted shouldBe
          List("boto3", "flask", "grpc", "request-object")
  }

  "flask route decorator yields an entrypoint, route metadata and parameter sources" in {
      val cpg = code("""from flask import Flask, request
            |app = Flask(__name__)
            |@app.route("/cmd", methods=["POST"])
            |def run_cmd(user_id):
            |    name = request.form["name"]
            |    return name + user_id
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("framework-route").method.name.l should contain("run_cmd")
          cpg.tag.nameExact("framework-input").parameter.name.l should contain("user_id")
          cpg.tag.nameExact("route-path").value.l should contain("/cmd")
          cpg.tag.nameExact("http-method").value.l should contain("POST")
      }
  }

  "fastapi pydantic model fields bound to a handler parameter are sources" in {
      val cpg = code("""from pydantic import BaseModel
            |api = None
            |class Item(BaseModel):
            |    name: str
            |    cmd: str
            |@api.post("/items")
            |async def create(item: Item):
            |    return item.cmd
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("framework-input").parameter.name.l should contain("item")
          cpg.tag.nameExact("framework-input").call.code.l should contain("item.cmd")
      }
  }

  "aiohttp request-object handler parameters are sources" in {
      val cpg = code("""from aiohttp import web
            |async def handle(request):
            |    n = request.query.get("n")
            |    return web.Response(text=n)
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("framework-route").method.name.l should contain("handle")
          cpg.tag.nameExact("framework-input").parameter.name.l should contain("request")
      }
  }

  "a helper that merely accepts a request is not an entry point" in {
      // Regression guard. Tagging every method with a `request` parameter as a route made
      // helpers, predicates and middleware into entry points whose EVERY parameter was
      // attacker-controlled - `framework-route` is itself a source tag, so this fed reachables
      // directly. It is the same false-positive shape as the filename-keyed PY_REQUEST_PATTERNS
      // that Part C of this task deleted, keyed on a parameter name instead of a file name.
      val cpg = code("""from flask import Flask, request
            |app = Flask(__name__)
            |def log_request(request, level):
            |    return str(request) + level
            |def build_context(request, template_name, extra_vars):
            |    return {"t": template_name}
            |class Middleware:
            |    def process(self, request, response):
            |        return response
            |""".stripMargin)

      withRecognizers(cpg) {
          val routes = cpg.tag.nameExact("framework-route").method.name.l
          routes should not contain "log_request"
          routes should not contain "build_context"
          routes should not contain "process"

          // The request object itself is still a source wherever it is passed...
          cpg.tag.nameExact("framework-input").parameter.name.l should contain("request")
          // ...but the unrelated parameters of a non-handler are not, and a response object
          // must never be tagged as attacker input.
          val sources = cpg.tag.nameExact("framework-input").parameter.name.l
          sources should not contain "level"
          sources should not contain "template_name"
          sources should not contain "extra_vars"
          sources should not contain "response"
      }
  }

  "a django function view is still a full entry point with its url parameters" in {
      val cpg = code("""from django.http import HttpResponse
            |def profile(request, uid):
            |    return HttpResponse(uid)
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("framework-route").method.name.l should contain("profile")
          val sources = cpg.tag.nameExact("framework-input").parameter.name.l
          // the URL keyword argument of a real view IS attacker-controlled
          sources should contain("uid")
          sources should contain("request")
      }
  }

  "frontend-synthesized methods are never tagged as routes" in {
      // The frontend emits <body>, <fakeNew>, <metaClassCallHandler> and a <metaClassAdapter>
      // copy of every real method. None is an entry point; tagging them inflated route counts
      // and put framework-route on __init__.
      val cpg = code("""from flask import Flask, request
            |app = Flask(__name__)
            |class Log:
            |    def __init__(self, request):
            |        self.r = request
            |""".stripMargin)

      withRecognizers(cpg) {
          val routes = cpg.tag.nameExact("framework-route").method.name.l
          routes should not contain "__init__"
          routes.filter(n => n.startsWith("<") || n.contains("<metaClass")) shouldBe empty
      }
  }

  "grpc servicer request parameters are sources (bare class and generated base)" in {
      val cpg = code("""import grpc
            |class Greeter:
            |    def SayHello(self, req, context):
            |        return req.name
            |class Streamer(GreeterServicer):
            |    def ListThings(self, request, context):
            |        return request.query
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("framework-input").parameter.name.l should contain("req")
          cpg.tag.nameExact("framework-input").parameter.name.l should contain("request")
          cpg.tag.nameExact("framework-route").method.name.l should contain("SayHello")
      }
  }

  "mcp tool arguments carry the dedicated mcp-input tag" in {
      val cpg = code("""from mcp.server.fastmcp import FastMCP
            |mcp = FastMCP("demo")
            |@mcp.tool()
            |def shell(cmd: str) -> str:
            |    return cmd
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("mcp-input").parameter.name.l should contain("cmd")
          cpg.tag.nameExact("framework-route").method.name.l should contain("shell")
      }
  }

  "AI/LLM prompt construction, invocation and composition are tagged" in {
      val cpg = code("""from langchain.prompts import PromptTemplate
            |from langchain_openai import ChatOpenAI
            |def llm(user_input):
            |    tpl = PromptTemplate.from_template("Answer: {q}")
            |    chain = tpl | ChatOpenAI(model="gpt-4")
            |    return chain.invoke({"q": user_input})
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("ai-prompt").call.name.l should contain("from_template")
          cpg.tag.nameExact("ai-invoke").call.name.l should contain("invoke")
          cpg.tag.nameExact("ai-compose").call.name.l should contain("<operator>.or")
      }
  }

  "boto3 reads and writes are service-ingress / service-egress" in {
      val cpg = code("""import boto3
            |s3 = boto3.client("s3")
            |def fetch(key):
            |    obj = s3.get_object(Bucket="b", Key=key)
            |    return obj["Body"].read()
            |def store(key, data):
            |    s3.put_object(Bucket="b", Key=key, Body=data)
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("service-ingress").call.name.l should contain("get_object")
          cpg.tag.nameExact("service-egress").call.name.l should contain("put_object")
      }
  }

  "a lambda event handler is an entrypoint with event as source" in {
      val cpg = code("""def lambda_handler(event, context):
            |    return event["body"]
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("framework-route").method.name.l should contain("lambda_handler")
          cpg.tag.nameExact("framework-input").parameter.name.l should contain("event")
          // context is not attacker-controlled
          cpg.tag.nameExact("framework-input").parameter.name.l should not contain "context"
      }
  }

  "celery tasks and sqlalchemy select() are recognized" in {
      val cpg = code("""from celery import Celery
            |import sqlalchemy
            |app = Celery("tasks")
            |@app.task
            |def process(user_id):
            |    return user_id
            |def query():
            |    return select(1)
            |""".stripMargin)

      withRecognizers(cpg) {
          cpg.tag.nameExact("framework-route").method.name.l should contain("process")
          cpg.tag.nameExact("framework-input").parameter.name.l should contain("user_id")
          cpg.tag.nameExact("sql").call.name.l should contain("select")
      }
  }
end PythonFrameworkRecognizerTests
