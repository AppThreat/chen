package io.appthreat.x2cpg.passes.taggers.java

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** Framework taint vocabulary for Java graphs (javasrc2cpg, and the JVM byte-code frontends whose
  * shapes overlap).
  *
  * This object is the single documented home of the Java framework shapes the taggers key on - the
  * same role [[io.appthreat.dataflowengineoss.semantics.PhpFrameworkSemantics]] plays for PHP.
  * Every part is consumed by `x2cpg`'s `ChennaiTagsPass.tagJavaRoutes` (routes, inputs, outputs)
  * and `EasyTagsPass.tagJavaPatterns` (family inventory: http-client, sql, ai, cloud, native, sdk),
  * which is the vocabulary atom's reachable slicing queries.
  *
  * The shapes reflect how javasrc2cpg actually lowers the constructs:
  *   - `@GetMapping("/x")` -> an ANNOTATION node named `GetMapping` whose `value` parameter carries
  *     the path literal as an AST child;
  *   - `import org.springframework...` -> an IMPORT node whose `importedEntity` is the qualified
  *     name (the import gate below);
  *   - `void doGet(HttpServletRequest req, HttpServletResponse resp)` -> METHOD_PARAMETER_IN nodes
  *     whose `typeFullName` ends with the servlet type names;
  *   - `class H implements RequestHandler<String,String>` -> a TYPE_DECL whose
  *     `inheritsFromTypeFullName` contains the interface name;
  *   - unresolved calls (`router.get("/x")` with no Router on the classpath) keep the bare method
  *     name and the full source text in `code`, so router registrations are matched on `code`.
  *
  * Naming-collision discipline: a bare annotation name like `Get` or a bare call name like `query`
  * also occurs outside the framework, so the recognizers only accept a bare name when the project
  * imports the owning package ([[usesImports]]), and prefer fully-qualified shapes (parameter
  * types, `methodFullName` prefixes) where the frontend can produce them.
  */
object JavaFrameworks:

  /** True when the graph imports anything under one of the given roots. A root matches a prefix of
    * the dotted import path, so `springframework` covers
    * `org.springframework.web.bind.annotation.GetMapping`.
    */
  def usesImports(cpg: Cpg, roots: String*): Boolean =
    val entities = cpg.imports.importedEntity.l
    entities.exists { entity =>
        roots.exists(root =>
            entity == root ||
                entity.startsWith(s"$root.") ||
                entity.endsWith(s".$root") ||
                entity.contains(s".$root.")
        )
    }

  // ---------------------------------------------------------------------------------------------
  // HTTP: Spring MVC/WebFlux, JAX-RS/Jakarta REST (RESTEasy, Quarkus, Micronaut-compatible),
  // servlets, and router-DSL registrations (Vert.x, Javalin, Spark).
  // ---------------------------------------------------------------------------------------------

  object Http:

    /** Spring request-mapping annotations; the route literal is their `value`/`path` member. */
    val springMappingAnnotations: Seq[String] =
        Seq(
          "GetMapping",
          "PostMapping",
          "PutMapping",
          "DeleteMapping",
          "PatchMapping",
          "RequestMapping"
        )

    /** Spring request-data annotations: a parameter carrying one is web-facing by definition. */
    val springParamAnnotations: Seq[String] =
        Seq(
          "RequestParam",
          "RequestBody",
          "PathVariable",
          "RequestHeader",
          "RequestPart",
          "ModelAttribute",
          "CookieValue"
        )

    /** Spring controller stereotypes: a handler in such a class writes the response body. */
    val springControllerAnnotations: Seq[String] =
        Seq("RestController", "Controller")

    /** JAX-RS/Jakarta REST verb annotations (`@GET`, `@POST`, ...). Bare names - gated on a
      * `jakarta.ws.rs`/`javax.ws.rs` import so a user `@GET` cannot fire.
      */
    val jaxRsVerbAnnotations: Seq[String] =
        Seq("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

    /** JAX-RS path annotation, on the class and/or the method. */
    val jaxRsPathAnnotation: String = "Path"

    /** JAX-RS request-data parameter annotations. */
    val jaxRsParamAnnotations: Seq[String] =
        Seq(
          "QueryParam",
          "PathParam",
          "FormParam",
          "HeaderParam",
          "CookieParam",
          "BeanParam",
          "MatrixParam"
        )

    val jaxRsImportRoots: Seq[String] = Seq("jakarta.ws.rs", "javax.ws.rs")

    /** Micronaut method annotations (`@Get`, `@Post`, ...): bare names, gated on
      * `io.micronaut.http` (an unprefixed `@Get` would collide with anything).
      */
    val micronautImportRoots: Seq[String] = Seq("io.micronaut.http", "io.micronaut")

    /** Servlet entrypoint methods; the servlet gate below disambiguates `service`. */
    val servletMethods: Seq[String] =
        Seq("doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace", "service")

    /** A parameter of one of these types is the request (framework-input); the Response type is the
      * response (framework-output).
      */
    val servletRequestTypes: Seq[String] =
        Seq("HttpServletRequest", "ServletRequest")
    val servletResponseTypes: Seq[String] =
        Seq("HttpServletResponse", "ServletResponse")

    /** Router-DSL registrations: `router.get("/path")`, `app.post("/path", handler)`,
      * `server.delete("/:id")`. Matched on the call's code because an unresolvable receiver leaves
      * nothing better than the source text.
      */
    val routerCallRegex: String =
        "^(?i)(router|route|app|server|api|endpoints|paths)\\.(get|post|put|delete|patch|head|options|route|addRoute|add|all)\\(.*"

    /** Call names that attach a handler to a route in the router DSLs. */
    val routerHandlerCallNames: Seq[String] =
        Seq("handler", "handlerFor", "addHandler", "blockingHandler")

    /** Vert.x routing-context type: a parameter of this type is the web-facing input. */
    val routingContextTypes: Seq[String] = Seq("RoutingContext", "io.vertx.ext.web.RoutingContext")

    /** Vert.x request/response accessors on the routing context. */
    val contextRequestCallNames: Seq[String] =
        Seq(
          "getParam",
          "queryParams",
          "queryParam",
          "pathParam",
          "pathParams",
          "body",
          "getBodyAsJson",
          "request",
          "getHeader",
          "formDataAttributes",
          "fileUploads"
        )
  end Http

  // ---------------------------------------------------------------------------------------------
  // gRPC services: generated `*ImplBase` overrides with a StreamObserver response parameter.
  // ---------------------------------------------------------------------------------------------

  object Rpc:
    /** The response side of a gRPC service method: `StreamObserver<Reply> responseObserver`. */
    val streamObserverTypes: Seq[String] = Seq("StreamObserver", "io.grpc.stub.StreamObserver")

    /** The generated base classes every gRPC service implementation extends. */
    val grpcBaseTypeRegex: String = ".*(ImplBase|GrpcServiceImpBase)$"

    /** StreamObserver output methods - each sends a message to the client. */
    val observerOutputCalls: Seq[String] = Seq("onNext", "onError", "onCompleted")

    /** io.grpc import roots, for the (optional) project-level gate. */
    val grpcImportRoots: Seq[String] = Seq("io.grpc")

  // ---------------------------------------------------------------------------------------------
  // Database: JDBC, Spring JdbcTemplate, JPA/Hibernate, MyBatis, MongoDB, Redis.
  // ---------------------------------------------------------------------------------------------

  object Database:
    /** JDBC statement calls. `execute` is too generic to accept unconditionally, so the recognizer
      * also requires a first argument (the SQL) or a java.sql-typed receiver.
      */
    val jdbcCallNames: Seq[String] =
        Seq(
          "prepareStatement",
          "prepareCall",
          "createStatement",
          "executeQuery",
          "executeUpdate",
          "executeBatch",
          "executeLargeUpdate",
          "executeScript"
        )

    /** Spring JdbcTemplate / NamedParameterJdbcTemplate data methods; import-gated. */
    val jdbcTemplateImportRoots: Seq[String] = Seq("org.springframework.jdbc")

    /** EntityManager / Session data methods - Hibernate, EclipseLink, Spring Data JPA. */
    val jpaCallNames: Seq[String] =
        Seq(
          "createQuery",
          "createNativeQuery",
          "createStoredProcedureQuery",
          "persist",
          "merge",
          "remove"
        )

    /** Annotations whose string member IS a database statement. */
    val queryAnnotations: Seq[String] =
        Seq(
          "Query",
          "Select",
          "Insert",
          "Update",
          "Delete",
          "SelectProvider",
          "InsertProvider",
          "UpdateProvider",
          "DeleteProvider"
        )

    /** Document/key-value stores; methodFullName prefixes when resolvable, import roots otherwise.
      */
    val documentStoreImportRoots: Seq[String] =
        Seq(
          "com.mongodb",
          "org.mongodb",
          "org.springframework.data.mongodb",
          "redis",
          "org.springframework.data.redis"
        )
  end Database

  // ---------------------------------------------------------------------------------------------
  // AI/ML: LangChain4j, Spring AI, OpenAI SDK, Google GenAI, Bedrock, Azure OpenAI.
  // ---------------------------------------------------------------------------------------------

  object AiLlm:
    val importRoots: Seq[String] = Seq(
      "dev.langchain4j",
      "org.springframework.ai",
      "com.openai",
      "com.google.genai",
      "com.google.ai.generativelanguage",
      "software.amazon.awssdk.services.bedrockruntime",
      "com.azure.ai",
      "com.theokanning.openai"
    )

    /** Model/chain invocation call names across the Java AI SDKs. Bare names - import-gated. */
    val invocationCallNames: Seq[String] =
        Seq(
          "generate",
          "chat",
          "chatCompletion",
          "createChatCompletion",
          "complete",
          "invokeModel",
          "converse",
          "converseStream",
          "generateContent",
          "streamContent",
          "generateText",
          "embed",
          "embedAll",
          "generateImage"
        )

    /** Prompt-construction call names (the fluent Spring AI/LangChain4j builders). */
    val promptCallNames: Seq[String] =
        Seq("prompt", "system", "user", "parameters", "messages", "template")
  end AiLlm

  // ---------------------------------------------------------------------------------------------
  // MCP (Model Context Protocol) servers: @Tool methods and server-exchange parameters.
  // ---------------------------------------------------------------------------------------------

  object Mcp:
    val importRoots: Seq[String] =
        Seq("io.modelcontextprotocol", "org.springframework.ai.tool")

    /** The tool annotation (MCP java-sdk and Spring AI spell it identically). */
    val toolAnnotations: Seq[String] = Seq("Tool", "McpTool")

    /** A parameter of one of these types receives the live server exchange. */
    val exchangeTypes: Seq[String] =
        Seq("McpSyncServerExchange", "McpAsyncServerExchange", "McpServerExchange")

  // ---------------------------------------------------------------------------------------------
  // Cloud: AWS SDK v1/v2, Google Cloud, Azure; serverless function handlers.
  // ---------------------------------------------------------------------------------------------

  object Cloud:
    /** methodFullName/import prefixes of the big three clouds. */
    val importRoots: Seq[String] =
        Seq(
          "software.amazon.awssdk",
          "com.amazonaws",
          "com.google.cloud",
          "com.azure",
          "com.microsoft.azure"
        )

    /** Serverless function interfaces: an implementation's entry method is web/event-facing. */
    val handlerInterfaceNames: Seq[String] =
        Seq("RequestHandler", "RequestStreamHandler", "FunctionInvoker")

    val handlerEntryMethods: Seq[String] =
        Seq("handleRequest", "apply", "accept", "handleRequestStream")

  // ---------------------------------------------------------------------------------------------
  // Native interop: JNI and the FFM API (java.lang.foreign, Java 22+).
  // ---------------------------------------------------------------------------------------------

  object Native:
    /** Library-loading calls - the JNI boundary setup. */
    val libraryLoadCallNames: Seq[String] = Seq("loadLibrary", "load")

    /** The FFM API package, and its characteristic entry calls. */
    val foreignPackageRoots: Seq[String] = Seq("java.lang.foreign")
    val foreignCallNames: Seq[String] =
        Seq("nativeLinker", "downcallHandle", "upcallStub", "allocate", "getUtf8String")

    /** MethodHandle invocation - the actual native call of a downcall handle. */
    val methodHandleCallNames: Seq[String] = Seq("invokeExact", "invoke", "invokeWithArguments")

  // ---------------------------------------------------------------------------------------------
  // SDK: messaging (Kafka, JMS, RabbitMQ), HTTP clients (OkHttp, java.net.http, Retrofit, Feign).
  // ---------------------------------------------------------------------------------------------

  object Sdk:
    /** Listener annotations: a message-driven entrypoint, the queue equivalent of a route. */
    val listenerAnnotations: Seq[String] =
        Seq(
          "KafkaListener",
          "JmsListener",
          "RabbitListener",
          "RabbitHandler",
          "MessageMapping",
          "StreamListener",
          "ServiceActivator",
          "EventListener",
          "Scheduled",
          "Subscribe"
        )

    val messagingImportRoots: Seq[String] =
        Seq(
          "org.springframework.kafka",
          "org.springframework.amqp",
          "org.springframework.jms",
          "org.springframework.cloud.stream",
          "org.springframework.scheduling"
        )

    /** Outbound HTTP client shapes, as methodFullName prefixes (resolved) or import roots. */
    val httpClientPackages: Seq[String] =
        Seq(
          "okhttp3",
          "retrofit2",
          "feign",
          "com.squareup.okhttp",
          "org.springframework.web.client",
          "org.springframework.web.reactive.function.client",
          "java.net.http",
          "org.apache.http",
          "org.asynchttpclient",
          "io.ktor.client",
          "com.mashape.unirest",
          "khttp",
          "org.eclipse.jetty.client"
        )

    /** Characteristic call names of the fluent HTTP clients, import-gated. */
    val httpClientCallNames: Seq[String] =
        Seq(
          "newCall",
          "enqueue",
          "execute",
          "send",
          "retrieve",
          "exchange",
          "getForObject",
          "postForObject",
          "getForEntity",
          "postForEntity"
        )
  end Sdk
end JavaFrameworks
