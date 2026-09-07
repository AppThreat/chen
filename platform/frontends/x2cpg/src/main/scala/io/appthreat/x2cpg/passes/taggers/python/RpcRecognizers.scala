package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import PythonRecognizerUtil.*

/** B4 - gRPC servicers. A class inheriting `*Servicer` (including the generated
  * `..._pb2_grpc.<Service>Servicer` bases) is an RPC endpoint; every servicer method's `request`
  * parameter is a source.
  *
  * Structure used: `inheritsFromTypeFullName` last segment (`grpc.py:<module>.Servicer`,
  * `helloworld_pb2_grpc.GreeterServicer`). The `context` parameter is deliberately NOT a source. NB
  * (Task 5 input): the generated stubs carry the real request message type on the parameter
  * annotation; a type-based request-parameter rule would be more precise than the name-based one.
  */
object GrpcRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "grpc"

  private val RequestParamNames = Set("request", "req")

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, Set("grpc"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    val servicerClasses = cpg.typeDecl
        .filter(td => td.inheritsFromTypeFullName.exists(_.endsWith("Servicer")))
        .name.l
    val inherited =
        if servicerClasses.isEmpty then Nil
        else
          val pattern = servicerClasses
              .map(n => "(?s).*\\." + java.util.regex.Pattern.quote(n) + "\\.[^.]+")
              .mkString("|")
          cpg.method.fullName(pattern).filter(isUserMethod).l
    val inheritedIds = inherited.map(_.id()).toSet
    // Bare servicer classes (hand-written before codegen linking): the
    // (self, req|request, context) parameter shape is the stub signature.
    val bySignature = cpg.method.internal
        .filter(isUserMethod)
        .filter { m =>
          val names = m.parameter.name.l.toSet
          names.exists(RequestParamNames.contains) && names.contains("context")
        }
        .filterNot(m => inheritedIds.contains(m.id()))
        .l
    (inherited ++ bySignature).foreach { method =>
      tag(method, ROUTE_TAG)
      method.parameter.l
          .filter(p => RequestParamNames.contains(p.name))
          .foreach(p => tag(p, INPUT_TAG))
    }
  end run
end GrpcRecognizer

/** B4 - Model Context Protocol. Tool/resource/prompt functions (`@mcp.tool()`,
  * `@mcp.resource("x")`, `@mcp.prompt()`) receive attacker-controlled arguments by construction.
  * Their parameters are tagged `mcp-input` - a dedicated tag, NOT a reuse of `framework-input`
  * (atom's reachables treat it as a source tag in its own right).
  */
object McpRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "mcp"

  private val McpDecorators = Set("tool", "resource", "prompt")

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, Set("mcp"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    val mcpFunctions = cpg.annotation.l
        .filter(a => McpDecorators.contains(lastSegment(a.name.toLowerCase)))
        .flatMap(_.inAst.collectAll[io.shiftleft.codepropertygraph.generated.nodes.Method])
        .filter(isUserMethod)
        .l
    mcpFunctions.foreach(tagHandler(_, MCP_INPUT_TAG))
