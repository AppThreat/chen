package io.appthreat.x2cpg.passes.taggers

/** Framework taint vocabulary for Java graphs (javasrc2cpg, and the JVM byte-code frontends whose
  * shapes overlap).
  *
  * This object is the single documented home of the Java framework shapes the taggers key on - the
  * same role `PhpFrameworkSemantics` (in `dataflowengineoss`) plays for PHP - referenced by name
  * rather than as a scaladoc link, because `x2cpg` does not depend on that module.
  *
  * Every value here is consumed by `x2cpg`'s `ChennaiTagsPass.tagJavaRoutes` (routes, inputs,
  * outputs) and `EasyTagsPass.tagJavaPatterns` (family inventory: http-client, sql, ai, cloud,
  * native, sdk), which is the vocabulary atom's reachable slicing queries.
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
  *     name and lose the receiver, so router registrations are matched on the call name plus a
  *     route-shaped literal argument, under an import gate.
  *
  * Naming-collision discipline: a bare annotation name like `Get` or a bare call name like `query`
  * also occurs outside the framework, so the recognizers only accept a bare name when the project
  * imports the owning package (`ChennaiTagsPass.usesImports`), and prefer fully-qualified shapes
  * (parameter types, `methodFullName` prefixes) where the frontend can produce them.
  */
object JavaFrameworks:

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

    /** RESTEasy Reactive request-data parameter annotations (Quarkus REST): a parameter carrying one
      * receives client data. A sibling of [[jaxRsParamAnnotations]] rather than part of it, because
      * the owning package is `org.jboss.resteasy.reactive`, not `jakarta.ws.rs`.
      */
    val resteasyReactiveParamAnnotations: Seq[String] =
        Seq("RestQuery", "RestPath", "RestForm", "RestHeader", "RestCookie", "RestMatrix")

    val resteasyReactiveImportRoot: String = "org.jboss.resteasy.reactive"

    /** Quarkus declarative reactive routes: `io.quarkus.vertx.web.Route` on a method (repeatable),
      * `RouteBase` supplying a class-level path prefix, and `RouteFilter` marking a filter invoked on
      * every request.
      */
    val quarkusRouteImportRoot: String = "io.quarkus.vertx.web"
    val quarkusRouteAnnotations: Seq[String] = Seq("Route")
    val quarkusRouteBaseAnnotation: String = "RouteBase"
    val quarkusRouteFilterAnnotation: String = "RouteFilter"

    /** Request-injection parameter annotations of a `@Route` method, from the same package. */
    val quarkusRouteParamAnnotations: Seq[String] = Seq("Param", "Header", "Body")

    /** Micronaut method annotations (`@Get`, `@Post`, ...): bare names, gated on the `io.micronaut`
      * import root (an unprefixed `@Get` would collide with anything).
      */
    val micronautImportRoots: Seq[String] = Seq("io.micronaut")

    /** Servlet entrypoint methods; the servlet gate below disambiguates `service`. */
    val servletMethods: Seq[String] =
        Seq("doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace", "service")

    /** Import roots that open the router-DSL recognizer. `io.vertx.ext.web` is Vert.x 3/4/5 core,
      * `io.vertx.reactivex.ext.web` the RxJava2 bindings of Vert.x 4, and `io.vertx.mutiny.ext.web`
      * / `io.vertx.rxjava3.ext.web` the Mutiny and RxJava3 bindings Quarkus and Vert.x 5 use (a
      * Quarkus bean registers routes on `@Observes io.vertx.mutiny.ext.web.Router`).
      */
    val routerImportRoots: Seq[String] =
        Seq(
          "io.vertx.ext.web",
          "io.vertx.reactivex.ext.web",
          "io.vertx.mutiny.ext.web",
          "io.vertx.rxjava3.ext.web",
          "io.javalin",
          "spark.Spark",
          "io.vertx.core.http"
        )

    /** Call names that attach a handler to a route in the router DSLs. */
    val routerHandlerCallNames: Seq[String] =
        Seq("handler", "handlerFor", "addHandler", "blockingHandler")

    /** Vert.x request/response accessors on the routing context. `getBodyAsJson` is gone in Vert.x
      * 5 (kept for Vert.x 4 code); there the body is read through `body()` returning `RequestBody`,
      * whose `asString`/`asJsonObject`/`asJsonArray`/`asPojo` results are request data.
      */
    val contextRequestCallNames: Seq[String] =
        Seq(
          "getParam",
          "queryParams",
          "queryParam",
          "pathParam",
          "pathParams",
          "body",
          "getBodyAsJson",
          "asString",
          "asJsonObject",
          "asJsonArray",
          "asPojo",
          "request",
          "getHeader",
          "formDataAttributes",
          "fileUploads"
        )

    /** `RequestBody.buffer` is request data too, but `buffer` is an everyday method name, so it is
      * only accepted on a receiver the graph resolved to `io.vertx.ext.web.RequestBody` (the
      * Mutiny/Rx bindings wrap it, and those wrappers keep the same simple name in the resolved
      * full name).
      */
    val requestBodyBufferFullNamePrefixes: Seq[String] =
        Seq("io.vertx.ext.web.RequestBody.buffer", "io.vertx.mutiny.ext.web.RequestBody.buffer")
  end Http

  // ---------------------------------------------------------------------------------------------
  // gRPC services: generated `*ImplBase` overrides with a StreamObserver response parameter, and
  // Quarkus Mutiny services (`@GrpcService` classes returning Uni/Multi, no StreamObserver).
  // ---------------------------------------------------------------------------------------------

  object Rpc:
    /** StreamObserver output methods - each sends a message to the client. */
    val observerOutputCalls: Seq[String] = Seq("onNext", "onError", "onCompleted")

    /** Quarkus marks its Mutiny gRPC services with `io.quarkus.grpc.GrpcService`; the class
      * implements the generated Mutiny interface, so each public service method takes the request
      * message and returns the reply (wrapped in `Uni`/`Multi`).
      */
    val quarkusGrpcImportRoot: String = "io.quarkus.grpc"
    val quarkusGrpcServiceAnnotation: String = "GrpcService"

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

    /** EntityManager / Session query builders - Hibernate, EclipseLink, Spring Data JPA.
      * Distinctive enough to accept without a gate.
      */
    val jpaQueryCallNames: Seq[String] =
        Seq("createQuery", "createNativeQuery", "createStoredProcedureQuery")

    /** EntityManager entity operations - `persist`/`merge`/`remove` are everyday collection and
      * cache method names, so they are only accepted in a project that imports a persistence API.
      */
    val jpaEntityCallNames: Seq[String] = Seq("persist", "merge", "remove")
    val jpaImportRoots: Seq[String] =
        Seq("jakarta.persistence", "javax.persistence", "org.hibernate", "org.springframework.orm")

    /** Repository write calls of Jakarta Data and Quarkus Data. Neither API spells the EntityManager
      * trio: Jakarta Data repositories declare writes as `insert`/`update`/`delete`/`save` (the
      * `CrudRepository`/`BasicRepository` methods and the matching lifecycle annotations), and
      * Quarkus Data repositories expose `persist`/`persistAndFlush`/`delete`. `persist` therefore
      * lives in both lists, gated by its own root here because `jakarta.data` has no `persist`.
      * `delete`/`update`/`save`/`insert` are everyday names, so a RESOLVED call must additionally
      * name a repository type (the declaring class of a Jakarta Data or Quarkus Data write is the
      * user's `*Repository` interface); unresolved calls keep the bare name under the import gate.
      */
    val dataImportRoots: Seq[String] = Seq("jakarta.data", "io.quarkus.data")
    val dataWriteCallNames: Seq[String] =
        Seq("insert", "update", "delete", "save", "persist", "persistAndFlush")

    /** Annotations whose string member IS a database statement. `HQL` and `SQL` are Hibernate's
      * `org.hibernate.annotations.processing` statement annotations; `Query` covers both Spring
      * Data's and Jakarta Data's. `Find` (Hibernate/Jakarta Data) carries no statement and is
      * deliberately absent.
      */
    val queryAnnotations: Seq[String] =
        Seq(
          "Query",
          "HQL",
          "SQL",
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

    /** Prompt-construction call names (the fluent Spring AI/LangChain4j builders). Only distinctive
      * names: `system`/`user`/`parameters` are everyday method names and would fabricate prompt
      * sinks on unrelated helpers even inside an AI project.
      */
    val promptCallNames: Seq[String] =
        Seq("prompt", "systemMessage", "userMessage", "aiMessage", "messages", "template")
  end AiLlm

  // ---------------------------------------------------------------------------------------------
  // MCP (Model Context Protocol) servers: @Tool methods and server-exchange parameters.
  // ---------------------------------------------------------------------------------------------

  object Mcp:
    val importRoots: Seq[String] =
        Seq("io.modelcontextprotocol", "org.springframework.ai.tool", "io.quarkiverse.mcp.server")

    /** The tool annotation (MCP java-sdk, Spring AI and Quarkus MCP Server spell it identically).
      * `Prompt` and `ResourceTemplate` are the Quarkus MCP Server variants a client drives with
      * argument values (through `@PromptArg`/`@ResourceTemplateArg`); a plain `Resource` exposes a
      * fixed URI and takes no client-chosen input, so it is absent.
      */
    val toolAnnotations: Seq[String] = Seq("Tool", "McpTool", "Prompt", "ResourceTemplate")

    /** A `@Tool` method of LangChain4j (`dev.langchain4j.agent.tool.Tool`) is called by the model,
      * not by a remote MCP client, so it must not become an `mcp-tool` route. The annotation full
      * name carries the owning package, which is the only discriminator once a graph imports both
      * frameworks and both annotations share the simple name `Tool`.
      */
    val excludedToolImportRoots: Seq[String] = Seq("dev.langchain4j")

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
    /** Library-loading calls - the JNI boundary setup. Only `loadLibrary` is accepted as a bare
      * name: `load` is an everyday method name and `System.load` is matched through
      * `methodFullName` instead, where the declaring class is unambiguous.
      */
    val libraryLoadCallNames: Seq[String] = Seq("loadLibrary")
    val libraryLoadFullNames: Seq[String] = Seq("java.lang.System.load.*")

    /** The FFM API package, and its characteristic entry calls. `allocate` is deliberately absent:
      * it is an everyday buffer-builder name, and resolved FFM calls are covered by the
      * `java.lang.foreign.*` methodFullName prefix.
      */
    val foreignPackageRoots: Seq[String] = Seq("java.lang.foreign")
    val foreignCallNames: Seq[String] =
        Seq("nativeLinker", "downcallHandle", "upcallStub", "getUtf8String")

    /** MethodHandle invocation - the actual native call of a downcall handle. */
    val methodHandleCallNames: Seq[String] = Seq("invokeExact", "invoke", "invokeWithArguments")

  // ---------------------------------------------------------------------------------------------
  // SDK: messaging (Kafka, JMS, RabbitMQ), HTTP clients (OkHttp, java.net.http, Retrofit, Feign).
  // ---------------------------------------------------------------------------------------------

  object Sdk:
    /** Listener annotations: a message-driven entrypoint, the queue equivalent of a route. All
      * names are messaging frameworks - `@Scheduled` (a cron tick carries no external data) and
      * `@EventListener` (in-process events) are deliberately absent: neither is an input boundary,
      * and tagging them manufactures taint sources.
      */
    val listenerAnnotations: Seq[String] =
        Seq(
          "KafkaListener",
          "JmsListener",
          "RabbitListener",
          "RabbitHandler",
          "MessageMapping",
          "StreamListener",
          "ServiceActivator",
          "Subscribe"
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
