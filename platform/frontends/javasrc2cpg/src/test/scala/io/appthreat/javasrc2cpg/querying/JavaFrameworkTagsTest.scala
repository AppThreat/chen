package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** Java framework boundary semantics: which methods are web-facing, where request data enters,
  * where response data leaves, and which calls reach databases, LLMs, message queues, cloud
  * services and native code.
  *
  * Each group names the framework family it pins and the tag vocabulary the slicer consumes:
  *
  *   - `framework-route` - a route registration (the path literal and the handler method)
  *   - `framework-input` - web-facing input (handler parameters, request accessors)
  *   - `framework-output` - web-facing output (response parameters, response writers)
  *   - `http-client`/`http-endpoint` - outbound HTTP calls and their URL literals
  *   - `sql`, `db-read`, `ai-llm`, `mcp-tool`, `grpc-service`, `cloud`, `native`, `sdk-call`
  *
  * The fixtures are deliberately dependency-free: only the shapes the recognizers key on (import
  * names, annotations, parameter types, call names) appear, so the tests run without the frameworks
  * on the classpath.
  */
class JavaFrameworkTagsTest extends JavaSrcCode2CpgFixture:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  "Spring Web MVC" should {

      "tag @GetMapping handlers, their route literal and their parameters" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import org.springframework.web.bind.annotation.GetMapping;
            |import org.springframework.web.bind.annotation.RequestParam;
            |import org.springframework.web.bind.annotation.RestController;
            |
            |@RestController
            |public class UserController {
            |    @GetMapping("/users/{id}")
            |    public String getUser(@RequestParam("id") String id) {
            |        return "user:" + id;
            |    }
            |}
            |""".stripMargin,
            "UserController.java"
          ))

          val routeMethods = cpg.method.name("getUser").l
          routeMethods should not be empty
          // javasrc2cpg lowers an annotation's string value to an ANNOTATION_LITERAL under
          // parameterAssign.value (not a LITERAL node).
          cpg.literal
              .codeExact("\"/users/{id}\"")
              .where(_.tag.name("framework-route"))
              .l should not be empty
          cpg.method.name("getUser").where(_.tag.name("framework-route")).l should not be empty
          cpg.parameter.name("id").where(_.tag.name("framework-input")).l should not be empty
      }

      "tag relative, root and array-mapped routes, and only value/path members" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import org.springframework.web.bind.annotation.GetMapping;
            |import org.springframework.web.bind.annotation.RequestMapping;
            |import org.springframework.web.bind.annotation.RestController;
            |import org.springframework.http.MediaType;
            |
            |@RestController
            |@RequestMapping("/api")
            |public class C {
            |    @GetMapping("users")
            |    public String a() { return "a"; }
            |
            |    @GetMapping("/")
            |    public String b() { return "b"; }
            |
            |    @RequestMapping({"/x", "/y"})
            |    public String c() { return "c"; }
            |
            |    @GetMapping(value = "/z", produces = MediaType.APPLICATION_JSON_VALUE)
            |    public String d() { return "d"; }
            |}
            |""".stripMargin,
            "RouteShapes.java"
          ))

          // Relative segment (class-level prefix), root route, both array members, the explicit
          // value= member, and the class-level prefix itself - and NOT the produces media type.
          cpg.literal
              .where(_.tag.name("framework-route"))
              .code
              .l
              .sorted shouldBe List(
            "\"/\"",
            "\"/api\"",
            "\"/x\"",
            "\"/y\"",
            "\"/z\"",
            "\"users\""
          )
      }

      "tag @PostMapping with a @RequestBody parameter as web-facing input" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import org.springframework.web.bind.annotation.PostMapping;
            |import org.springframework.web.bind.annotation.RequestBody;
            |import org.springframework.web.bind.annotation.RestController;
            |
            |@RestController
            |public class OrderController {
            |    @PostMapping("/orders")
            |    public String create(@RequestBody String body) {
            |        return body;
            |    }
            |}
            |""".stripMargin,
            "OrderController.java"
          ))

          cpg.parameter.name("body").where(_.tag.name("framework-input")).l should not be empty
          cpg.literal
              .codeExact("\"/orders\"")
              .where(_.tag.name("framework-route"))
              .l should not be empty
      }
  }

  "Router gating" should {

      "not open on a user type merely named Router (a Map.get is not a route)" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import java.util.HashMap;
            |import java.util.Map;
            |
            |class MessageRouter {}
            |
            |public class Config {
            |    void install(MessageRouter router) { }
            |
            |    String lookup() {
            |        Map<String, String> map = new HashMap<>();
            |        return map.get("/config/path");
            |    }
            |}
            |""".stripMargin,
            "Config.java"
          ))

          cpg.literal.where(_.tag.name("framework-route")).l shouldBe empty
      }
  }

  "JAX-RS / Jakarta REST (RESTEasy, Quarkus, Micronaut-compatible)" should {

      "tag @Path-annotated resource methods with their verb and params" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import jakarta.ws.rs.GET;
            |import jakarta.ws.rs.Path;
            |import jakarta.ws.rs.PathParam;
            |import jakarta.ws.rs.QueryParam;
            |
            |@Path("/library")
            |public class LibraryResource {
            |    @GET
            |    @Path("/books/{id}")
            |    public String book(@PathParam("id") String id, @QueryParam("q") String q) {
            |        return id + q;
            |    }
            |}
            |""".stripMargin,
            "LibraryResource.java"
          ))

          cpg.method.name("book").where(_.tag.name("framework-route")).l should not be empty
          cpg.parameter.name("id").where(_.tag.name("framework-input")).l should not be empty
          cpg.parameter.name("q").where(_.tag.name("framework-input")).l should not be empty
      }

      "tag RESTEasy Reactive parameter annotations on their own, annotated or not alongside them" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import jakarta.ws.rs.GET;
            |import jakarta.ws.rs.Path;
            |import jakarta.ws.rs.core.Context;
            |import jakarta.ws.rs.core.UriInfo;
            |import org.jboss.resteasy.reactive.RestQuery;
            |
            |@Path("/items")
            |public class ItemResource {
            |    @GET
            |    public String find(@RestQuery String q, @Context UriInfo info) {
            |        return q + info.getPath();
            |    }
            |}
            |""".stripMargin,
            "ItemResource.java"
          ))

          // The explicit vocabulary pins the @RestQuery parameter as request data independently of
          // the whole-resource-method rule that tags every parameter of a handler.
          cpg.parameter.name("q").where(_.tag.name("framework-input")).l should not be empty
      }

      "leave a RestQuery-lookalike alone without the resteasy-reactive import" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class LocalRest {
            |    public String find(@RestQuery String q) { return q; }
            |
            |    @interface RestQuery {}
            |}
            |""".stripMargin,
            "LocalRest.java"
          ))

          cpg.parameter.name("q").where(_.tag.name("framework-input")).l shouldBe empty
      }
  }

  "Quarkus declarative reactive routes" should {

      "tag @Route handlers, their path literal, injected parameters and derived paths" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.quarkus.vertx.web.Route;
            |import io.quarkus.vertx.web.Param;
            |import io.vertx.ext.web.RoutingContext;
            |
            |public class MyRoutes {
            |    @Route(path = "/hello", methods = Route.HttpMethod.GET)
            |    String hello(@Param String name) {
            |        return "hello " + name;
            |    }
            |
            |    @Route(methods = Route.HttpMethod.GET)
            |    void greetingsQueryParam(RoutingContext rc) {
            |        rc.response().end("hi");
            |    }
            |
            |    @Route(regex = "/numbers/.*")
            |    void numbers(RoutingContext rc) {
            |        rc.response().end("hi");
            |    }
            |}
            |""".stripMargin,
            "MyRoutes.java"
          ))

          cpg.literal
              .codeExact("\"/hello\"")
              .where(_.tag.name("framework-route"))
              .l should not be empty
          // A regex member is a route literal too, with its metacharacters intact.
          cpg.literal
              .codeExact("\"/numbers/.*\"")
              .where(_.tag.name("framework-route"))
              .l should not be empty
          cpg.method.name("hello").where(_.tag.name("framework-route")).l should not be empty
          cpg.parameter.name("name").where(_.tag.name("framework-input")).l should not be empty
          cpg.parameter.name("rc").where(_.tag.name("framework-input")).l should not be empty
          // Neither path nor regex: the served path is the de-camel-cased method name.
          cpg.method.name("greetingsQueryParam")
              .where(_.tag.nameExact("route-path").valueExact("/greetings-query-param"))
              .l should not be empty
      }

      "compose a RouteBase class prefix onto the method path" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.quarkus.vertx.web.Route;
            |import io.quarkus.vertx.web.RouteBase;
            |
            |@RouteBase(path = "/api")
            |public class BasedRoutes {
            |    @Route(path = "/items")
            |    String items() { return "[]"; }
            |}
            |""".stripMargin,
            "BasedRoutes.java"
          ))

          cpg.method.name("items")
              .where(_.tag.nameExact("route-path").valueExact("/api/items"))
              .l should not be empty
      }

      "tag @RouteFilter methods as request handlers" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.quarkus.vertx.web.RouteFilter;
            |import io.vertx.ext.web.RoutingContext;
            |
            |public class Filters {
            |    @RouteFilter(20)
            |    void addHeader(RoutingContext rc) {
            |        rc.response().putHeader("X-Filter", "1");
            |    }
            |}
            |""".stripMargin,
            "Filters.java"
          ))

          cpg.method.name("addHeader").where(_.tag.name("framework-route")).l should not be empty
          cpg.parameter.name("rc").where(_.tag.name("framework-input")).l should not be empty
      }

      "leave a Route-lookalike alone without the io.quarkus.vertx.web import" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class TrainTimetable {
            |    @Route(path = "/trains")
            |    String next() { return "10:00"; }
            |
            |    @interface Route { String path(); }
            |}
            |""".stripMargin,
            "TrainTimetable.java"
          ))

          cpg.method.name("next").where(_.tag.name("framework-route")).l shouldBe empty
          cpg.literal.codeExact("\"/trains\"").where(_.tag.name("framework-route")).l shouldBe empty
      }
  }

  "Servlets" should {

      "tag doGet/doPost parameters as request/response boundaries" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import java.io.IOException;
            |import jakarta.servlet.http.HttpServlet;
            |import jakarta.servlet.http.HttpServletRequest;
            |import jakarta.servlet.http.HttpServletResponse;
            |
            |public class LegacyServlet extends HttpServlet {
            |    @Override
            |    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            |        String v = req.getParameter("v");
            |        resp.getWriter().println(v);
            |    }
            |}
            |""".stripMargin,
            "LegacyServlet.java"
          ))

          cpg.parameter.name("req").where(_.tag.name("framework-input")).l should not be empty
          cpg.parameter.name("resp").where(_.tag.name("framework-output")).l should not be empty
      }
  }

  "Vert.x routers" should {

      "tag route literals and this::handler method-reference handlers" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.vertx.ext.web.Router;
            |import io.vertx.ext.web.RoutingContext;
            |
            |public class VertxApp {
            |    public void install(Router router) {
            |        router.get("/api/items").handler(this::handleItems);
            |    }
            |
            |    private void handleItems(RoutingContext ctx) {
            |        ctx.response().end(ctx.request().getParam("q"));
            |    }
            |}
            |""".stripMargin,
            "VertxApp.java"
          ))

          cpg.literal
              .codeExact("\"/api/items\"")
              .where(_.tag.name("framework-route"))
              .l should not be empty
          cpg.method.name("handleItems").where(_.tag.name("framework-route")).l should not be empty
          cpg.parameter.name("ctx").where(_.tag.name("framework-input")).l should not be empty
      }

      "resolve an overloaded method-reference handler to nothing rather than to an arbitrary one" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.vertx.ext.web.Router;
            |import io.vertx.ext.web.RoutingContext;
            |
            |public class VertxOverloadApp {
            |    public void install(Router router) {
            |        router.get("/api/items").handler(this::handle);
            |    }
            |
            |    private void handle(RoutingContext ctx) {
            |        ctx.response().end(ctx.request().getParam("q"));
            |    }
            |
            |    private void handle(String message) {}
            |}
            |""".stripMargin,
            "VertxOverloadApp.java"
          ))

          // The reference carries no discriminator: the arity the target must have comes from the
          // functional interface it is passed to, which is a library type absent from the graph.
          // Picking either overload on a coin flip would tag a handler and every parameter of it
          // as a taint SOURCE, so neither is picked.
          //
          // The route literal is unaffected - it is read from the call, not from the handler.
          cpg.literal
              .codeExact("\"/api/items\"")
              .where(_.tag.name("framework-route"))
              .l should not be empty
          cpg.method.name("handle").where(_.tag.name("framework-route")).l shouldBe empty
          // The `String` overload is the one an arbitrary pick could have chosen: tagging its
          // parameter would invent a request-data source out of a name collision.
          cpg.parameter.name("message").where(_.tag.name("framework-input")).l shouldBe empty
          // `ctx` IS framework-input, and not because of anything resolved here: a RoutingContext
          // parameter is request data in whatever method it appears, tagged by its own type rule.
          // That rule is what bounds this fix - it prevents the false route, not every tag a
          // wrongly-picked handler would have attracted.
          cpg.parameter.name("ctx").where(_.tag.name("framework-input")).l should not be empty
      }

      "leave a `handler` call alone in a project with no router DSL on the classpath" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class EventBus {
            |    private final java.util.List<Runnable> registered = new java.util.ArrayList<>();
            |
            |    public void install() {
            |        handler(this::process);
            |        addHandler(this::process);
            |    }
            |
            |    void handler(Runnable r) { registered.add(r); }
            |    void addHandler(Runnable r) { registered.add(r); }
            |
            |    private void process() {}
            |}
            |""".stripMargin,
            "EventBus.java"
          ))

          // `handler`/`addHandler` are ordinary names: logging, event buses, exception dispatch.
          // Tagging these made `process` a route and every parameter of it a taint SOURCE.
          cpg.method.name("process").where(_.tag.name("framework-route")).l shouldBe empty
      }

      "tag routes registered on the Mutiny router alone (Vert.x 5 / Quarkus)" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.vertx.mutiny.ext.web.Router;
            |import io.vertx.ext.web.RoutingContext;
            |import jakarta.enterprise.context.ApplicationScoped;
            |import jakarta.enterprise.event.Observes;
            |
            |@ApplicationScoped
            |public class MutinyRoutes {
            |    void init(@Observes Router router) {
            |        router.get("/mutiny").handler(this::serve);
            |    }
            |
            |    private void serve(RoutingContext rc) {
            |        rc.response().end("ok");
            |    }
            |}
            |""".stripMargin,
            "MutinyRoutes.java"
          ))

          // The only router-flavoured import is the Mutiny binding; the core io.vertx.ext.web
          // import appears solely for the RoutingContext handler parameter.
          cpg.literal
              .codeExact("\"/mutiny\"")
              .where(_.tag.name("framework-route"))
              .l should not be empty
          cpg.method.name("serve").where(_.tag.name("framework-route")).l should not be empty
      }

      "tag the Vert.x 5 request body accessors as request data" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.vertx.ext.web.RoutingContext;
            |
            |public class BodyReader {
            |    void read(RoutingContext rc) {
            |        String s = rc.body().asString();
            |        Object o = rc.body().asJsonObject();
            |        Object a = rc.body().asJsonArray();
            |        Object p = rc.body().asPojo(java.lang.Object.class);
            |        Object b = rc.body().buffer();
            |        rc.response().end(s);
            |    }
            |}
            |""".stripMargin,
            "BodyReader.java"
          ))

          Seq("asString", "asJsonObject", "asJsonArray", "asPojo").foreach { name =>
              cpg.call.name(name).where(_.tag.name("framework-input")).l should not be empty
          }
          // `buffer` is an everyday method name: without a receiver the graph resolved to
          // RequestBody, the call stays untagged rather than manufacturing request data.
          cpg.call.name("buffer").where(_.tag.name("framework-input")).l shouldBe empty
      }
  }

  "gRPC services" should {

      "tag StreamObserver service methods as bidirectional framework boundaries" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.grpc.stub.StreamObserver;
            |
            |public class GreeterServiceImpl extends GreeterGrpc.GreeterImplBase {
            |    @Override
            |    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
            |        responseObserver.onNext(HelloReply.newBuilder().setMessage(request.getName()).build());
            |        responseObserver.onCompleted();
            |    }
            |}
            |""".stripMargin,
            "GreeterServiceImpl.java"
          ))

          val sayHello = cpg.method.name("sayHello")
          sayHello.where(_.tag.name("grpc-service")).l should not be empty
          cpg.parameter.name("request").where(_.tag.name("framework-input")).l should not be empty
          cpg.parameter.name("responseObserver").where(_.tag.name("framework-output")).l should not be empty
      }

      "leave a same-named StreamObserver alone when io.grpc is not imported" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import com.example.rx.StreamObserver;
            |
            |public class LocalStream {
            |    public void publish(String payload, StreamObserver<String> observer) {
            |        observer.onNext(payload);
            |    }
            |}
            |""".stripMargin,
            "LocalStream.java"
          ))

          cpg.method.name("publish").where(_.tag.name("grpc-service")).l shouldBe empty
          cpg.parameter.name("payload").where(_.tag.name("framework-input")).l shouldBe empty
      }

      "tag Quarkus Mutiny gRPC services: request in, returned Uni out" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.quarkus.grpc.GrpcService;
            |import io.smallrye.mutiny.Uni;
            |
            |@GrpcService
            |public class Greeter implements HelloGrpc {
            |    @Override
            |    public Uni<HelloReply> sayHello(HelloRequest request) {
            |        return Uni.createFrom().item(HelloReply.newBuilder().setMessage(request.getName()).build());
            |    }
            |}
            |""".stripMargin,
            "Greeter.java"
          ))

          val sayHello = cpg.method.name("sayHello").l
          sayHello.where(_.tag.name("grpc-service")).l should not be empty
          sayHello.where(_.tag.name("framework-route")).l should not be empty
          cpg.parameter.name("request").where(_.tag.name("framework-input")).l should not be empty
          // The returned Uni wraps the reply message, so the return is the output boundary.
          cpg.method.name("sayHello").methodReturn.where(_.tag.name("framework-output")).l should not be empty
      }

      "keep the StreamObserver arm working inside a Quarkus gRPC project" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.quarkus.grpc.GrpcService;
            |import io.grpc.stub.StreamObserver;
            |
            |@GrpcService
            |public class LegacyGreeter extends GreeterGrpc.GreeterImplBase {
            |    @Override
            |    public void sayHello(HelloRequest request, StreamObserver<HelloReply> responseObserver) {
            |        responseObserver.onNext(HelloReply.newBuilder().setMessage(request.getName()).build());
            |        responseObserver.onCompleted();
            |    }
            |}
            |""".stripMargin,
            "LegacyGreeter.java"
          ))

          val sayHello = cpg.method.name("sayHello")
          sayHello.where(_.tag.name("grpc-service")).l should not be empty
          cpg.parameter.name("request").where(_.tag.name("framework-input")).l should not be empty
          cpg.parameter.name("responseObserver").where(_.tag.name("framework-output")).l should not be empty
      }

      "leave a GrpcService-lookalike alone without the io.quarkus.grpc import" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class LocalGreeter {
            |    public String greet(String payload) { return payload; }
            |
            |    @interface GrpcService {}
            |}
            |""".stripMargin,
            "LocalGreeter.java"
          ))

          cpg.method.name("greet").where(_.tag.name("grpc-service")).l shouldBe empty
          cpg.parameter.name("payload").where(_.tag.name("framework-input")).l shouldBe empty
      }
  }

  "JDBC and JPA" should {

      "tag PreparedStatement execution and SQL literals" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import java.sql.Connection;
            |import java.sql.PreparedStatement;
            |import java.sql.ResultSet;
            |
            |public class UserDao {
            |    public String find(Connection connection, String id) throws Exception {
            |        PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
            |        statement.setString(1, id);
            |        ResultSet rs = statement.executeQuery();
            |        return rs.getString(1);
            |    }
            |}
            |""".stripMargin,
            "UserDao.java"
          ))

          cpg.call.name("prepareStatement").where(_.tag.name("sql")).l should not be empty
          cpg.call.name("executeQuery").where(_.tag.name("sql")).l should not be empty
      }

      "tag @Query annotation SQL as a route into the database" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import org.springframework.data.jpa.repository.Query;
            |import org.springframework.data.repository.Repository;
            |
            |public interface UserRepository extends Repository<User, String> {
            |    @Query("SELECT u FROM User u WHERE u.name = :name")
            |    User findByName(String name);
            |}
            |""".stripMargin,
            "UserRepository.java"
          ))

          cpg.literal
              .codeExact("\"SELECT u FROM User u WHERE u.name = :name\"")
              .where(_.tag.name("sql"))
              .l should not be empty
      }

      "tag Hibernate @HQL/@SQL and Jakarta Data @Query statements" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import jakarta.data.repository.CrudRepository;
            |import jakarta.data.repository.Repository;
            |import org.hibernate.annotations.processing.Find;
            |import org.hibernate.annotations.processing.HQL;
            |import org.hibernate.annotations.processing.SQL;
            |
            |@Repository
            |public interface BookRepository extends CrudRepository<Book, Long> {
            |    @HQL("where title = :title")
            |    java.util.List<Book> byTitle(String title);
            |
            |    @SQL("SELECT * FROM books WHERE isbn = :isbn")
            |    Book byIsbn(String isbn);
            |
            |    @Query("FROM Book WHERE author = :author")
            |    java.util.List<Book> byAuthor(String author);
            |
            |    @Find
            |    Book byPublisher(String publisher);
            |}
            |""".stripMargin,
            "BookRepository.java"
          ))

          cpg.literal
              .codeExact("\"where title = :title\"")
              .where(_.tag.name("sql"))
              .l should not be empty
          cpg.literal
              .codeExact("\"SELECT * FROM books WHERE isbn = :isbn\"")
              .where(_.tag.name("sql"))
              .l should not be empty
          cpg.literal
              .codeExact("\"FROM Book WHERE author = :author\"")
              .where(_.tag.name("sql"))
              .l should not be empty
          // @Find derives its query from the parameter names; it declares no statement string.
          cpg.literal
              .codeExact("\"publisher\"")
              .where(_.tag.name("sql"))
              .l shouldBe empty
      }

      "tag Jakarta Data repository writes and leave non-repository saves alone" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import jakarta.data.repository.CrudRepository;
            |import jakarta.data.repository.Repository;
            |
            |@Repository
            |public interface PersonRepository extends CrudRepository<Person, Long> {
            |}
            |""".stripMargin,
            "PersonRepository.java"
          ).moreCode(
            """
            |package com.example;
            |
            |public class PersonService {
            |    private final PersonRepository people;
            |    private final Prefs prefs = new Prefs();
            |
            |    public PersonService(PersonRepository people) { this.people = people; }
            |
            |    public Person add(Person p) {
            |        people.insert(p);
            |        people.save(p);
            |        prefs.save(p.toString());
            |        return p;
            |    }
            |}
            |
            |class Prefs {
            |    void save(String v) { }
            |}
            |""".stripMargin,
            "PersonService.java"
          ))

          cpg.call.name("insert").where(_.tag.name("sql")).l should not be empty
          cpg.call.name("save").where(_.tag.name("sql")).size shouldBe 1
          // `save` on the project's own Prefs helper is not a database write.
          cpg.call.name("save").where(_.methodFullName(".*Prefs.*")).where(_.tag.name("sql"))
              .l shouldBe empty
      }

      "leave repository-shaped calls alone without a data API import" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class Shelf {
            |    private final java.util.List<String> items = new java.util.ArrayList<>();
            |
            |    public void manage(String x) {
            |        items.add(x);
            |        persist(x);
            |    }
            |
            |    void persist(String x) { }
            |}
            |""".stripMargin,
            "Shelf.java"
          ))

          cpg.call.name("persist").where(_.tag.name("sql")).l shouldBe empty
      }
  }

  "AI/LLM clients" should {

      "tag LangChain4j model calls as ai-llm" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import dev.langchain4j.model.chat.ChatLanguageModel;
            |
            |public class Assistant {
            |    private final ChatLanguageModel model;
            |
            |    public Assistant(ChatLanguageModel model) { this.model = model; }
            |
            |    public String ask(String prompt) {
            |        return model.generate(prompt);
            |    }
            |}
            |""".stripMargin,
            "Assistant.java"
          ))

          cpg.call.name("generate").where(_.tag.name("ai-llm")).l should not be empty
      }

      "tag Spring AI ChatClient prompts as ai-llm" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import org.springframework.ai.chat.client.ChatClient;
            |
            |public class Advisor {
            |    private final ChatClient chatClient;
            |
            |    public Advisor(ChatClient chatClient) { this.chatClient = chatClient; }
            |
            |    public String consult(String question) {
            |        return chatClient.prompt().user(question).call().content();
            |    }
            |}
            |""".stripMargin,
            "Advisor.java"
          ))

          cpg.call.name("prompt").where(_.tag.name("ai-llm")).l should not be empty
      }
  }

  "MCP servers" should {

      "tag @Tool methods as remotely-invoked tool handlers" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.modelcontextprotocol.server.McpSyncServerExchange;
            |import org.springframework.ai.tool.annotation.Tool;
            |
            |public class WeatherTools {
            |    @Tool(description = "current weather for a city")
            |    public String currentWeather(McpSyncServerExchange exchange, String city) {
            |        return "sunny in " + city;
            |    }
            |}
            |""".stripMargin,
            "WeatherTools.java"
          ))

          cpg.method.name("currentWeather").where(_.tag.name("mcp-tool")).l should not be empty
          cpg.parameter.name("city").where(_.tag.name("framework-input")).l should not be empty
      }

      "tag Quarkus MCP Server tools and prompts" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.quarkiverse.mcp.server.Tool;
            |import io.quarkiverse.mcp.server.ToolArg;
            |import io.quarkiverse.mcp.server.Prompt;
            |import io.quarkiverse.mcp.server.PromptArg;
            |
            |public class AcmeTools {
            |    @Tool(description = "run a command")
            |    String run(@ToolArg(description = "the command") String cmd) {
            |        return cmd;
            |    }
            |
            |    @Prompt(description = "greet someone")
            |    String greet(@PromptArg String who) {
            |        return "hello " + who;
            |    }
            |}
            |""".stripMargin,
            "AcmeTools.java"
          ))

          cpg.method.name("run").where(_.tag.name("mcp-tool")).l should not be empty
          cpg.method.name("run").where(_.tag.name("framework-route")).l should not be empty
          cpg.parameter.name("cmd").where(_.tag.name("framework-input")).l should not be empty
          // A prompt get passes the client's argument values, so the method is client-driven too.
          cpg.method.name("greet").where(_.tag.name("mcp-tool")).l should not be empty
          cpg.parameter.name("who").where(_.tag.name("framework-input")).l should not be empty
      }

      "not tag LangChain4j @Tool methods as MCP tools even when both frameworks are imported" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import io.modelcontextprotocol.server.McpSyncServerExchange;
            |
            |public class McpTypes {
            |    public static String exchange(McpSyncServerExchange exchange) { return ""; }
            |}
            |""".stripMargin,
            "McpTypes.java"
          ).moreCode(
            """
            |package com.example;
            |
            |import dev.langchain4j.agent.tool.Tool;
            |
            |public class ModelTools {
            |    @Tool("upper-case the text")
            |    public String shout(String text) {
            |        return text.toUpperCase();
            |    }
            |}
            |""".stripMargin,
            "ModelTools.java"
          ).moreCode(
            """
            |package com.example;
            |
            |import io.modelcontextprotocol.server.McpSyncServerExchange;
            |import io.quarkiverse.mcp.server.Tool;
            |
            |public class McpServer {
            |    @Tool(description = "echo")
            |    public String echo(McpSyncServerExchange exchange, String value) {
            |        return value;
            |    }
            |}
            |""".stripMargin,
            "McpServer.java"
          ))

          // The graph-wide import gate is open (io.modelcontextprotocol is imported in McpSide),
          // which by itself would tag BOTH `@Tool`s. The annotation's full name keeps them apart:
          // the LangChain4j tool is invoked by the model, so it is no client-facing boundary.
          cpg.method.name("shout").where(_.tag.name("mcp-tool")).l shouldBe empty
          cpg.parameter.name("text").where(_.tag.name("framework-input")).l shouldBe empty
          cpg.method.name("echo").where(_.tag.name("mcp-tool")).l should not be empty
      }
  }

  "Cloud SDKs" should {

      "tag AWS Lambda handleRequest parameters as framework input" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import com.amazonaws.services.lambda.runtime.Context;
            |import com.amazonaws.services.lambda.runtime.RequestHandler;
            |
            |public class UpperCaseHandler implements RequestHandler<String, String> {
            |    @Override
            |    public String handleRequest(String input, Context context) {
            |        return input.toUpperCase();
            |    }
            |}
            |""".stripMargin,
            "UpperCaseHandler.java"
          ))

          cpg.method.name("handleRequest").where(_.tag.name("cloud")).l should not be empty
          cpg.parameter.name("input").where(_.tag.name("framework-input")).l should not be empty
      }

      "tag AWS SDK v2 service clients as cloud calls" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import software.amazon.awssdk.services.s3.S3Client;
            |import software.amazon.awssdk.services.s3.model.GetObjectRequest;
            |
            |public class Store {
            |    public byte[] fetch(S3Client client, String key) {
            |        return client.getObject(GetObjectRequest.builder().key(key).build());
            |    }
            |}
            |""".stripMargin,
            "Store.java"
          ))

          cpg.call.name("getObject").where(_.tag.name("cloud")).l should not be empty
      }
  }

  "Native interop" should {

      "tag System.loadLibrary and native methods" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class NativeMath {
            |    static { System.loadLibrary("nativemath"); }
            |
            |    public native long fastSum(long[] values, int offset);
            |
            |    public long total(long[] values) { return fastSum(values, 0); }
            |}
            |""".stripMargin,
            "NativeMath.java"
          ))

          cpg.call.name("loadLibrary").where(_.tag.name("native")).l should not be empty
          cpg.method.name("fastSum").where(_.tag.name("native")).l should not be empty
      }

      "tag java.lang.foreign downcall setups as native" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import java.lang.foreign.FunctionDescriptor;
            |import java.lang.foreign.Linker;
            |import java.lang.invoke.MethodHandle;
            |
            |public class ForeignBridge {
            |    public MethodHandle strlen() {
            |        return Linker.nativeLinker().downcallHandle("strlen",
            |            FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG));
            |    }
            |}
            |""".stripMargin,
            "ForeignBridge.java"
          ))

          cpg.call.name("downcallHandle").where(_.tag.name("native")).l should not be empty
      }
  }

  "Message queues and HTTP client SDKs" should {

      "tag @KafkaListener methods as message-driven input" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import org.springframework.kafka.annotation.KafkaListener;
            |import org.springframework.stereotype.Service;
            |
            |@Service
            |public class OrderConsumer {
            |    @KafkaListener(topics = "orders", groupId = "billing")
            |    public void consume(String order) {
            |        process(order);
            |    }
            |
            |    void process(String order) { }
            |}
            |""".stripMargin,
            "OrderConsumer.java"
          ))

          // The listener method is an entrypoint (framework-route); its parameters carry the
          // incoming message (framework-input).
          cpg.method.name("consume").where(_.tag.name("framework-route")).l should not be empty
          cpg.parameter.name("order").where(_.tag.name("framework-input")).l should not be empty
      }

      "not tag @Scheduled or @EventListener methods as input boundaries" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import org.springframework.scheduling.annotation.Scheduled;
            |import org.springframework.context.event.EventListener;
            |import org.springframework.stereotype.Component;
            |
            |@Component
            |public class Jobs {
            |    @Scheduled(fixedRate = 1000)
            |    public void cleanup() { }
            |
            |    @EventListener
            |    public void onInternal(String evt) { }
            |}
            |""".stripMargin,
            "Jobs.java"
          ))

          // A cron tick carries no attacker-controlled data; an in-process event is not web
          // input. Neither may be manufactured into a taint source.
          cpg.method.name("cleanup|onInternal").where(_.tag.name("framework-input")).l shouldBe empty
          cpg.parameter.name("evt").where(_.tag.name("framework-input")).l shouldBe empty
      }

      "tag OkHttp call building as http-client with its URL literal" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import okhttp3.OkHttpClient;
            |import okhttp3.Request;
            |import okhttp3.Response;
            |
            |public class Fetcher {
            |    public String load(OkHttpClient client, String host) throws Exception {
            |        Request request = new Request.Builder().url("https://" + host + "/api/data").build();
            |        try (Response response = client.newCall(request).execute()) {
            |            return response.body().string();
            |        }
            |    }
            |}
            |""".stripMargin,
            "Fetcher.java"
          ))

          cpg.call.name("newCall").where(_.tag.name("http-client")).l should not be empty
      }

      // The import gate matches a root as a whole dotted segment. Matching it as a bare substring
      // (`contains("redis.")` rather than `contains(".redis.")`) makes an unrelated package whose
      // name merely ENDS in the root - `com.myredis` - open the gate for the whole graph.
      "not open an import gate on a package that merely ends in the root's name" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import com.myredis.Client;
            |
            |public class NotRedis {
            |    public Object read(MyTemplate t, String k) {
            |        return t.findById(k);
            |    }
            |}
            |
            |class MyTemplate {
            |    Object findById(String k) { return null; }
            |}
            |""".stripMargin,
            "NotRedis.java"
          ))

          cpg.call.name("findById").where(_.tag.name("sql")).l shouldBe empty
      }
  }

  "JDK sink families (EasyTagsPass parity with the Python arm)" should {

      "tag Runtime.exec and ProcessBuilder.start as code-execution" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class Launcher {
            |    public void run(String cmd) throws Exception {
            |        Runtime.getRuntime().exec("sh -c " + cmd);
            |        new ProcessBuilder("ls", cmd).start();
            |    }
            |}
            |""".stripMargin,
            "Launcher.java"
          ))

          cpg.call.name("exec").where(_.tag.name("code-execution")).l should not be empty
      }

      "tag file stream constructors as file-io" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import java.io.FileInputStream;
            |import java.io.IOException;
            |
            |public class Reader {
            |    public byte[] read(String path) throws IOException {
            |        try (FileInputStream in = new FileInputStream(path)) {
            |            return in.readAllBytes();
            |        }
            |    }
            |}
            |""".stripMargin,
            "Reader.java"
          ))

          cpg.call.name("<init>").where(_.tag.name("file-io")).l should not be empty
      }

      "tag ssrf only when the URL target is not a literal" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import java.io.InputStream;
            |import java.net.URL;
            |
            |public class Fetch {
            |    InputStream constantOnly() throws Exception {
            |        URL u = new URL("https://example.com/static");
            |        return u.openStream();
            |    }
            |
            |    InputStream variable(String target) throws Exception {
            |        URL u = new URL(target);
            |        return u.openStream();
            |    }
            |}
            |""".stripMargin,
            "Fetch.java"
          ))

          // The steerable construction is ssrf; the constant one is inventory only, and the
          // request calls themselves are http-client in both cases.
          val ssrfCodes = cpg.call.where(_.tag.name("ssrf")).code.l
          ssrfCodes shouldBe List("new URL(target)")
          cpg.call.name("openStream").where(_.tag.name("http-client")).l.size shouldBe 2
          cpg.call.name("openStream").where(_.tag.name("ssrf")).l shouldBe empty
      }

      "tag ObjectInputStream.readObject as unsafe-deserialization" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import java.io.IOException;
            |import java.io.ObjectInputStream;
            |
            |public class Deserializer {
            |    public Object load(ObjectInputStream in) throws IOException, ClassNotFoundException {
            |        return in.readObject();
            |    }
            |}
            |""".stripMargin,
            "Deserializer.java"
          ))

          cpg.call.name("readObject").where(_.tag.name("unsafe-deserialization")).l should not be empty
      }
  }
end JavaFrameworkTagsTest
