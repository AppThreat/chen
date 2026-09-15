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

          cpg.method.name("consume").where(_.tag.name("framework-input")).l should not be empty
          cpg.parameter.name("order").where(_.tag.name("framework-input")).l should not be empty
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
