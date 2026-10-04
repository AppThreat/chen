package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.{
    ControlStructureTypes,
    DispatchTypes,
    ModifierTypes
}
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Literal, Local, MethodRef}
import io.shiftleft.semanticcpg.language.*

/** The C++ the CDT frontend models with calls it makes up, as edg2atom builds it from edga. */
class CppShapesTests extends EdgCodeToCpgSuite:

  private def tagsOf(call: Call): Map[String, String] = call.tag.map(t => t.name -> t.value).l.toMap

  "new and delete" should {
      val cpg = code(
        """
        |struct Node {
        |  int value;
        |  Node *next;
        |  Node(int v) : value(v), next(nullptr) {}
        |  ~Node() { delete next; }
        |};
        |
        |int alloc_all(int n) {
        |  int *one = new int(7);
        |  int *many = new int[n];
        |  Node *node = new Node(3);
        |  int total = *one + many[0] + node->value;
        |  delete one;
        |  delete[] many;
        |  delete node;
        |  return total;
        |}
        |""".stripMargin
      )

      "be `<operator>.new` of the allocated type, tagged with its form" in {
          requireEdga()
          val news = cpg.call.nameExact("<operator>.new").l.sortBy(_.lineNumber.get)
          news.map(c => tagsOf(c)(X2CpgDefines.AllocFormTag)) shouldBe List(
            "scalar",
            "array",
            "scalar"
          )
          news.map(_.argument(1).code) shouldBe List("int", "int", "Node")
          news.head.argument(2).code shouldBe "7"
          news(1).argument(2).code shouldBe "n"
      }

      "call a constructor the graph holds, with its arguments" in {
          requireEdga()
          val nodeNew = cpg.call.nameExact("<operator>.new").filter(_.code == "new Node(3)").head
          inside(nodeNew.argument(2)) { case ctor: Call =>
              ctor.methodFullName shouldBe "Node.Node:void(int)"
              ctor.argument(1).code shouldBe "3"
          }
      }

      "be `<operator>.delete` of the pointer, with the destructor the graph holds" in {
          requireEdga()
          val deletes = cpg.method.nameExact("alloc_all").call.nameExact("<operator>.delete").l
              .sortBy(_.lineNumber.get)
          deletes.map(c => tagsOf(c)(X2CpgDefines.AllocFormTag)) shouldBe List(
            "scalar",
            "array",
            "scalar"
          )
          deletes.map(_.argument(1).code) shouldBe List("one", "many", "node")
          inside(deletes(2).argument(2)) { case dtor: Call =>
              dtor.name shouldBe "~Node"
              dtor.code shouldBe "node->~Node()"
          }
      }
  }

  "a class" should {
      val cpg = code(
        """
        |namespace geo {
        |struct Point {
        |  int x, y;
        |  Point() : x(0), y(0) {}
        |  Point(int a, int b) : x(a), y(b) {}
        |  ~Point() {}
        |  int sum() const { return x + y; }
        |  int scaled(int k) const;
        |  virtual int area() const { return this->x * y; }
        |  Point operator+(const Point &o) const { return Point(x + o.x, y + o.y); }
        |};
        |int Point::scaled(int k) const { return sum() * k; }
        |}
        |
        |int use(geo::Point *p, geo::Point &r) {
        |  geo::Point a(1, 2);
        |  geo::Point b;
        |  geo::Point c = a + b;
        |  int s = a.sum() + p->scaled(2) + r.area();
        |  if (s > 3) {
        |    geo::Point inner(3, 4);
        |    return inner.sum();
        |  }
        |  return s + c.x;
        |}
        |""".stripMargin
      )

      "hold the member functions defined in it, and a declaration of the others" in {
          requireEdga()
          val point = cpg.typeDecl.fullNameExact("geo.Point").head
          (point.astChildren.isMethod.name.l should contain).allOf(
            "Point",
            "~Point",
            "sum",
            "scaled",
            "area",
            "operator +"
          )
          val scaled = cpg.method.fullNameExact("geo.Point.scaled:int(int)").l
          scaled.size shouldBe 2
          scaled.count(_.block.astChildren.nonEmpty) shouldBe 1
      }

      "store a member initialiser's value into the member of the object being built" in {
          requireEdga()
          val ctor   = cpg.method.fullNameExact("geo.Point.Point:void(int,int)").head
          val stores = ctor.block.astChildren.isCall.nameExact("<operator>.assignment").l
          stores.map(_.code) shouldBe List("x(a)", "y(b)")
          inside(stores.head.argument(1)) { case access: Call =>
              access.name shouldBe "<operator>.indirectFieldAccess"
              access.argument(1).code shouldBe "this"
              access.argument(2).code shouldBe "x"
          }
      }

      "mark constructors, and give member functions no `this` parameter" in {
          requireEdga()
          val ctor = cpg.method.fullNameExact("geo.Point.Point:void(int,int)").head
          ctor.modifier.modifierType.l should contain(ModifierTypes.CONSTRUCTOR)
          ctor.parameter.name.l shouldBe List("a", "b")
      }

      "read members named without `this->` as identifiers, and `this` as a literal" in {
          requireEdga()
          val sum = cpg.method.nameExact("sum").filter(_.block.astChildren.nonEmpty).head
          sum.ast.isIdentifier.name.l shouldBe List("x", "y")
          // typed with the member's class, as the CDT frontend types them
          sum.ast.isIdentifier.typeFullName.l.distinct shouldBe List("geo.Point")
          val area = cpg.method.nameExact("area").head
          area.ast.isLiteral.code.l should contain("this")
      }

      "give a member call its object as argument 0" in {
          requireEdga()
          val sum =
              cpg.method.nameExact("use").call.nameExact("sum").filter(_.code == "a.sum()").head
          sum.argument(0).code shouldBe "a"
          val area = cpg.method.nameExact("use").call.nameExact("area").head
          area.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH
          area.receiver.code.l shouldBe List("r")
          // a member function called without `this->` has no object
          cpg.method.nameExact("scaled").call.nameExact("sum").argument.l shouldBe empty
      }

      "link an overloaded operator of the project, tagged with the operator it is written with" in {
          requireEdga()
          val plus = cpg.call.nameExact("operator +").head
          plus.methodFullName shouldBe "geo.Point.operator +:geo.Point(geo.Point &)"
          tagsOf(plus)(X2CpgDefines.OperatorCallTag) shouldBe "<operator>.addition"
          plus.argument(0).code shouldBe "a"
          plus.argument(1).code shouldBe "b"
      }

      "assign a constructed object the call to its constructor" in {
          requireEdga()
          val assignment = cpg.method.nameExact("use").call.nameExact("<operator>.assignment")
              .filter(_.argument(1).code == "a").head
          inside(assignment.argument(2)) { case ctor: Call =>
              ctor.methodFullName shouldBe "geo.Point.Point:void(int,int)"
              ctor.argument.code.l shouldBe List("1", "2")
          }
      }

      "destroy objects where their scope ends, and before a return that leaves it" in {
          requireEdga()
          val destructors = cpg.method.nameExact("use").call.nameExact("~Point").l
          def destroyedBy(statement: String) =
              cpg.method.nameExact("use").ast.isReturn.codeExact(statement).lineNumber.flatMap {
                  line =>
                      destructors.filter(_.lineNumber.contains(line)).sortBy(_.order).map(_.code)
              }.l
          // the early return destroys inner, then c, b and a; the last one c, b and a
          destroyedBy("return inner.sum();") shouldBe List(
            "inner.~Point()",
            "c.~Point()",
            "b.~Point()",
            "a.~Point()"
          )
          destroyedBy("return s + c.x;") shouldBe List("c.~Point()", "b.~Point()", "a.~Point()")
          // a return value that could observe them is computed first
          cpg.method.nameExact("use").local.nameExact("<return-value>").size shouldBe 2
          cpg.method.nameExact("use").assignment.code("<return-value> = .*").code.l.sorted shouldBe
              List("<return-value> = inner.sum()", "<return-value> = s + c.x")
      }
  }

  "a library's operator" should {
      val cpg = code(
        """
        |#include <vector>
        |int pick(std::vector<int> &v, int i) {
        |  v.push_back(i);
        |  return v[i];
        |}
        |""".stripMargin
      )

      "keep the shape of the built-in operator it is written with" in {
          requireEdga()
          val index =
              cpg.method.nameExact("pick").call.nameExact("<operator>.indirectIndexAccess").head
          index.argument.code.l shouldBe List("v", "i")
          cpg.method.nameExact("pick").call.name(".*operator.*\\[.*").l shouldBe empty
      }

      "leave a library member call its object as argument 0" in {
          requireEdga()
          val pushBack = cpg.method.nameExact("pick").call.nameExact("push_back").head
          pushBack.argument(0).code shouldBe "v"
          pushBack.argument(1).code shouldBe "i"
      }
  }

  "a lambda" should {
      val cpg = code(
        """
        |int run(int seed) {
        |  int base = 10;
        |  auto add = [base](int v) { return v + base; };
        |  return add(seed);
        |}
        |""".stripMargin
      )

      "be a METHOD of its own, referred to where it is written" in {
          requireEdga()
          val lambda = cpg.method.nameExact("anonymous_lambda_0").head
          lambda.fullName shouldBe "run:int(int).anonymous_lambda_0"
          cpg.method.nameExact("run").ast.collectAll[MethodRef].methodFullName.l shouldBe List(
            lambda.fullName
          )
          // a captured variable is the variable it copies
          lambda.ast.isIdentifier.name.l should contain("base")
      }

      "be called through its closure" in {
          requireEdga()
          val call = cpg.method.nameExact("run").call.nameExact("anonymous_lambda_0").head
          tagsOf(call)(X2CpgDefines.OperatorCallTag) shouldBe "<operator>()"
          call.receiver.code.l shouldBe List("add")
          call.argument(1).code shouldBe "seed"
      }
  }

  "a range-based for" should {
      val cpg = code(
        """
        |int total(const int (&values)[3]) {
        |  int sum = 0;
        |  for (int v : values) sum += v;
        |  return sum;
        |}
        |""".stripMargin
      )

      "be a FOR of the range, the loop variable and the body" in {
          requireEdga()
          val loop = cpg.controlStructure.controlStructureTypeExact(ControlStructureTypes.FOR).head
          loop.code shouldBe "for (int v:values)"
          loop.astChildren.collectAll[Identifier].name.l shouldBe List("values")
          loop.astChildren.collectAll[Local].name.l shouldBe List("v")
          loop.astChildren.isCall.code.l shouldBe List("sum += v")
      }
  }

  "a throw" should {
      val cpg = code(
        """
        |struct Error { Error(int c) : code(c) {} int code; };
        |int risky(int x) {
        |  if (x < 0) throw Error(x);
        |  return x;
        |}
        |""".stripMargin
      )

      "be `<operator>.throw` of the thrown value" in {
          requireEdga()
          val thrown = cpg.call.nameExact("<operator>.throw").head
          inside(thrown.argument(1)) { case ctor: Call =>
              ctor.methodFullName shouldBe "Error.Error:void(int)"
          }
      }
  }

  "a structured binding" should {
      val cpg = code(
        """
        |struct Span { char *data; unsigned long size; };
        |Span make_span(char *p, unsigned long n);
        |void note(const char *where);
        |unsigned long split(char *p, unsigned long n) {
        |  note(__func__);
        |  auto [data, size] = make_span(p, n);
        |  return data[0] + size;
        |}
        |""".stripMargin
      )

      "declare its object, named by the bindings, and assign each binding its part" in {
          requireEdga()
          val split = cpg.method.nameExact("split").head
          split.local.name.l shouldBe List("[data, size]", "data", "size")
          split.assignment.code.l shouldBe List(
            "[data, size] = make_span(p, n)",
            "data = [data, size].data",
            "size = [data, size].size"
          )
          split.ast.isIdentifier.nameExact("data").refsTo.l.map(_.label).distinct shouldBe List(
            "LOCAL"
          )
      }

      "leave the function name the front end predefines spelled as written" in {
          requireEdga()
          cpg.call.nameExact("note").argument(1).code.l shouldBe List("__func__")
      }
  }

  "what the front end knows beyond the code" should {
      val cpg = code(
        """
        |#define TWICE(x) ((x) * 2)
        |struct Lock { Lock(); ~Lock(); };
        |struct Base { virtual int area() const { return 0; } virtual ~Base() {} };
        |int scaled(int v, int factor = 3) { return v * factor; }
        |int sink(char *p);
        |int facts(const Base &b, int n) {
        |  Lock guard;
        |  char buf[n];
        |  buf[0] = 1;
        |  return b.area() + scaled(n) + TWICE(n) + sink(buf);
        |}
        |""".stripMargin
      )

      "be tags on the nodes it is about" in {
          requireEdga()
          def tagged(name: String) =
              cpg.method.nameExact("facts").ast.collectAll[
                io.shiftleft.codepropertygraph.generated.nodes.StoredNode
              ]
                  .flatMap(n => n.tag.nameExact(name).value.l.map(n.propertiesMap.get("CODE") -> _)).l
          tagged(X2CpgDefines.VirtualCallTag) shouldBe List("b.area()" -> "true")
          tagged(X2CpgDefines.DefaultArgumentTag).map(_._2) shouldBe List("true")
          tagged(X2CpgDefines.VlaSizeTag).map(_._2) shouldBe List("n")
          tagged(X2CpgDefines.LifetimeEndTag).map(_._2).distinct shouldBe List("guard")
          tagged(X2CpgDefines.CompilerGeneratedTag).map(_._1.toString) should contain(
            "guard.~Lock()"
          )
          tagged(X2CpgDefines.MacroOriginTag).map(_._2).exists(_.matches(".*:2:\\d+")) shouldBe true
      }
  }

  "a namespace-scope constant" should {
      val cpg = code(
        """
        |namespace io { namespace {
        |constexpr const unsigned long kBufferSize = 65536;
        |}
        |unsigned long room(unsigned long pos) { return kBufferSize - pos; }
        |}
        |""".stripMargin
      )

      "be assigned its value at the declaration, as the uses read it" in {
          requireEdga()
          inside(cpg.assignment.code("kBufferSize = .*").l) { case List(init) =>
              init.code shouldBe "kBufferSize = 65536"
              init.argument.argumentIndex(2).collectAll[Literal].code.l shouldBe List("65536")
          }
      }
  }
end CppShapesTests
