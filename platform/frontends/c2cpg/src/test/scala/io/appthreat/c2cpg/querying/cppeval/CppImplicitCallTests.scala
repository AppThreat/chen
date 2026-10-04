package io.appthreat.c2cpg.querying.cppeval

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, ModifierTypes, Operators}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** The calls C++ makes without spelling them as calls - overloaded operators, constructors,
  * destructors, smart-pointer `operator->`, template instances and lambdas - link to the METHOD the
  * graph holds for them.
  */
class CppImplicitCallTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private implicit val resolver: NoResolve.type = NoResolve

  private def tagsOf(call: Call, name: String): List[String] = call.tag.nameExact(name).value.l
  private def argsOf(call: Call): List[(Int, String)] =
      call.argument.l.map(a => a.argumentIndex -> a.code)

  private val vec2 = """
      |struct Vec2 {
      |  int x, y;
      |  Vec2() : x(0), y(0) {}
      |  Vec2(int a, int b) { x = a; y = b; }
      |  Vec2 operator+(const Vec2 &o) const { return Vec2(x + o.x, y + o.y); }
      |  Vec2 &operator=(const Vec2 &o) { x = o.x; y = o.y; return *this; }
      |  int operator[](int i) const { return i ? y : x; }
      |  bool operator==(const Vec2 &o) const { return x == o.x && y == o.y; }
      |  Vec2 &operator++() { ++x; return *this; }
      |  Vec2 operator++(int) { Vec2 t = *this; ++x; return t; }
      |};
      |Vec2 operator-(const Vec2 &a, const Vec2 &b) { return Vec2(a.x - b.x, a.y - b.y); }
      |struct Callable { int operator()(int v) { return v; } };
      |struct Plain { int v; };
      |""".stripMargin

  "user-defined operators" should {
      val cpg = code(s"""$vec2
          |int main() {
          |  Vec2 a(1, 2), c;
          |  Vec2 d{3, 4};
          |  c = a + d;
          |  c = a - d;
          |  int k = a[1];
          |  bool eq = a == c;
          |  ++a;
          |  a++;
          |  Callable cl;
          |  int r = cl(3);
          |  Plain p, q;
          |  p = q;
          |  return k + eq + r;
          |}
          |""".stripMargin)
      def callIn(code: String): Call = cpg.method.nameExact("main").call.codeExact(code).head

      "call a member operator on its first operand" in {
          val call = callIn("a + d")
          call.name shouldBe "operator +"
          call.methodFullName shouldBe "Vec2.operator +:Vec2(Vec2 &)"
          call.dispatchType shouldBe DispatchTypes.STATIC_DISPATCH
          call.typeFullName shouldBe "Vec2"
          argsOf(call) shouldBe List(0 -> "a", 1 -> "d")
          call.callee.fullName.l shouldBe List("Vec2.operator +:Vec2(Vec2 &)")
          tagsOf(call, X2CpgDefines.OperatorCallTag) shouldBe List(Operators.addition)
      }

      "call a free operator with both operands as arguments" in {
          val call = callIn("a - d")
          call.methodFullName shouldBe "operator -:Vec2(Vec2 &,Vec2 &)"
          argsOf(call) shouldBe List(1 -> "a", 2 -> "d")
          call.callee.isExternal.l shouldBe List(false)
          tagsOf(call, X2CpgDefines.OperatorCallTag) shouldBe List(Operators.subtraction)
      }

      "call the assignment operator with the assigned object first" in {
          val List(first, _) = cpg.method.nameExact("main").call.nameExact("operator =").l
          first.methodFullName shouldBe "Vec2.operator =:Vec2 &(Vec2 &)"
          argsOf(first) shouldBe List(0 -> "c", 1 -> "a + d")
          tagsOf(first, X2CpgDefines.OperatorCallTag) shouldBe List(Operators.assignment)
      }

      "call the subscript, comparison and increment operators" in {
          callIn("a[1]").methodFullName shouldBe "Vec2.operator []:int(int)"
          tagsOf(callIn("a[1]"), X2CpgDefines.OperatorCallTag) shouldBe List(
            Operators.indirectIndexAccess
          )
          callIn("a == c").methodFullName shouldBe "Vec2.operator ==:bool(Vec2 &)"
          callIn("++a").methodFullName shouldBe "Vec2.operator ++:Vec2 &()"
          callIn("a++").methodFullName shouldBe "Vec2.operator ++:Vec2(int)"
          tagsOf(callIn("a++"), X2CpgDefines.OperatorCallTag) shouldBe List(Operators.postIncrement)
      }

      "call a class's call operator on the object" in {
          val call = callIn("cl(3)")
          call.name shouldBe "operator ()"
          call.methodFullName shouldBe "Callable.operator ():int(int)"
          argsOf(call) shouldBe List(0 -> "cl", 1 -> "3")
          tagsOf(call, X2CpgDefines.OperatorCallTag) shouldBe List("<operator>()")
      }

      "keep the built-in operator for an assignment the compiler generates" in {
          val call = callIn("p = q")
          call.name shouldBe Operators.assignment
          call.tag.nameExact(X2CpgDefines.OperatorCallTag).l shouldBe empty
      }

      "give every operator method a caller" in {
          cpg.method.internal.name("operator.*").filter(_.callIn.isEmpty).name.l shouldBe empty
      }
  }

  "an operator declared only in a library header" should {
      val library = File.newTemporaryDirectory("cpp-library")
      sys.addShutdownHook(library.delete(swallowIOExceptions = true))
      (library / "libvec.h").writeText(
        """
          |struct LibVec {
          |  int x;
          |  LibVec operator+(const LibVec &o) const;
          |};
          |""".stripMargin
      )
      val cpg = code("""
          |#include "libvec.h"
          |int main() {
          |  LibVec a, b;
          |  LibVec c = a + b;
          |  return c.x;
          |}
          |""".stripMargin).withConfig(Config(includePaths = Set(library.pathAsString)))

      "keep the built-in operator: the graph holds no METHOD to link to" in {
          val call = cpg.method.nameExact("main").call.codeExact("a + b").head
          call.name shouldBe Operators.addition
          call.methodFullName shouldBe Operators.addition
      }
  }

  "a smart pointer's operator->" should {
      val cpg = code("""
          |struct Base { virtual void handle(int n) = 0; int count; };
          |struct Impl : Base { void handle(int n) override { count = n; } };
          |template <typename T> struct Ptr {
          |  T *p;
          |  explicit Ptr(T *q) : p(q) {}
          |  T *operator->() const { return p; }
          |  T &operator*() const { return *p; }
          |};
          |int main(int argc, char **argv) {
          |  Ptr<Base> b(new Impl());
          |  b->handle(argc);
          |  (*b).handle(argc);
          |  return b->count;
          |}
          |""".stripMargin)

      "call operator-> on the smart pointer and the method on its result" in {
          val call = cpg.method.nameExact("main").call.codeExact("b->handle(argc)").head
          call.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH
          (call.callee.fullName.l should contain).allOf(
            "Base.handle:void(int)",
            "Impl.handle:void(int)"
          )
          val receiver = call.receiver.isCall.head
          receiver.name shouldBe "operator ->"
          receiver.methodFullName shouldBe "Ptr.operator ->:ANY()"
          receiver.callee.isExternal.l shouldBe List(false)
          argsOf(receiver) shouldBe List(0 -> "b")
          tagsOf(receiver, X2CpgDefines.TemplateInstanceTag) shouldBe List("Base*()")
      }

      "call operator* for an explicit dereference" in {
          val deref = cpg.method.nameExact("main").call.codeExact("*b").head
          deref.methodFullName shouldBe "Ptr.operator *:ANY()"
          tagsOf(deref, X2CpgDefines.OperatorCallTag) shouldBe List(Operators.indirection)
      }

      "read a data member through what operator-> returns" in {
          val access =
              cpg.method.nameExact("main").call.nameExact(Operators.indirectFieldAccess).head
          access.argument(1).asInstanceOf[Call].name shouldBe "operator ->"
          access.typeFullName shouldBe "int"
      }
  }

  "constructors" should {
      val cpg = code(s"""$vec2
          |struct Guard { Guard(); ~Guard(); };
          |struct Holder { Guard g; int n; };
          |struct Owner { char *data; explicit Owner(char *d) { data = d; } };
          |void *operator new(unsigned long, void *place) { return place; }
          |int main(int argc, char **argv) {
          |  Vec2 a(1, 2);
          |  Vec2 c;
          |  Vec2 d{3, 4};
          |  Vec2 e = Vec2(5, 6);
          |  Guard guard;
          |  Plain plain;
          |  Owner *o = new Owner(argv[0]);
          |  char buf[sizeof(Vec2)];
          |  Vec2 *placed = new (buf) Vec2(7, 8);
          |  return a.x + c.x + d.x + e.x + o->data[0] + placed->x;
          |}
          |""".stripMargin)
      def callIn(code: String): Call = cpg.method.nameExact("main").call.codeExact(code)
          .filterNot(_.name == Operators.assignment).head

      "name constructors and destructors with a void return type" in {
          cpg.method.nameExact("Vec2").fullName.toSetMutable shouldBe Set(
            "Vec2.Vec2:void()",
            "Vec2.Vec2:void(int,int)"
          )
          cpg.method.nameExact("Vec2").methodReturn.typeFullName.toSetMutable shouldBe Set("void")
          cpg.method.nameExact("~Guard").fullName.l shouldBe List("Guard.~Guard:void()")
      }

      "mark every constructor as one, with or without an initializer list" in {
          cpg.method.nameExact("Vec2").l.map(_.modifier.modifierType.l.contains(
            ModifierTypes.CONSTRUCTOR
          )) shouldBe List(true, true)
          cpg.method.nameExact("Owner").modifier.modifierType.l should contain(
            ModifierTypes.CONSTRUCTOR
          )
      }

      "call the constructor for every declaration form" in {
          callIn("a(1, 2)").methodFullName shouldBe "Vec2.Vec2:void(int,int)"
          argsOf(callIn("a(1, 2)")) shouldBe List(1 -> "1", 2 -> "2")
          callIn("c").methodFullName shouldBe "Vec2.Vec2:void()"
          callIn("c").argument.l shouldBe empty
          callIn("d{3, 4}").methodFullName shouldBe "Vec2.Vec2:void(int,int)"
          argsOf(callIn("d{3, 4}")) shouldBe List(1 -> "3", 2 -> "4")
          callIn("Vec2(5, 6)").methodFullName shouldBe "Vec2.Vec2:void(int,int)"
          callIn("guard").methodFullName shouldBe "Guard.Guard:void()"
          List("a(1, 2)", "c", "d{3, 4}", "Vec2(5, 6)", "guard").foreach { c =>
              callIn(c).callee.isExternal.l shouldBe List(false)
          }
      }

      "assign each constructed object what its constructor builds" in {
          val assignments = cpg.method.nameExact("main").call.nameExact(Operators.assignment)
              .filter(_.argument(2).isCall).l
          (assignments.map(a => a.argument(1).code -> a.argument(2).code)
              .toSetMutable should contain).allOf(
            "a"     -> "a(1, 2)",
            "c"     -> "c",
            "d"     -> "d{3, 4}",
            "e"     -> "Vec2(5, 6)",
            "guard" -> "guard"
          )
          assignments.find(_.argument(1).code == "a").map(_.typeFullName) shouldBe Some("Vec2")
      }

      "call nothing for a class without a user-declared constructor" in {
          cpg.method.nameExact("main").call.codeExact("plain").l shouldBe empty
      }

      "construct a member in the class's constructors, not where it is declared" in {
          cpg.typeDecl.nameExact("Holder").method.l shouldBe empty
      }

      "nest the constructor call, holding its arguments, in new" in {
          val alloc = callIn("new Owner(argv[0])")
          alloc.name shouldBe "<operator>.new"
          tagsOf(alloc, X2CpgDefines.AllocFormTag) shouldBe List(X2CpgDefines.AllocFormScalar)
          val List(tpe, ctor: Call) = alloc.argument.l: @unchecked
          tpe.code shouldBe "Owner"
          ctor.methodFullName shouldBe "Owner.Owner:void(char*)"
          argsOf(ctor) shouldBe List(1 -> "argv[0]")
          ctor.typeFullName shouldBe "Owner"
      }

      "pass placement arguments to the operator new the project declares" in {
          val alloc = callIn("new (buf) Vec2(7, 8)")
          tagsOf(alloc, X2CpgDefines.AllocFormTag) shouldBe List(X2CpgDefines.AllocFormPlacement)
          val List(_, ctor: Call, operatorNew: Call) = alloc.argument.l: @unchecked
          ctor.methodFullName shouldBe "Vec2.Vec2:void(int,int)"
          operatorNew.name shouldBe "operator new"
          argsOf(operatorNew) shouldBe List(1 -> "buf")
          operatorNew.callee.isExternal.l shouldBe List(false)
      }
  }

  "copy-initialisation" should {
      val cpg = code("""
          |struct Name {
          |  const char *s;
          |  Name(const char *p) : s(p) {}
          |  Name(const Name &o) : s(o.s) {}
          |};
          |Name make();
          |int main() {
          |  Name a = "x";
          |  Name b = {"y"};
          |  Name c = Name("z");
          |  Name d = a;
          |  Name e = make();
          |  return 0;
          |}
          |""".stripMargin)
      def assignmentTo(name: String): Call = cpg.method.nameExact("main").call
          .nameExact(Operators.assignment).filter(_.argument(1).code == name).head

      "call the converting constructor for a value of another type" in {
          val ctor = assignmentTo("a").argument(2).asInstanceOf[Call]
          ctor.methodFullName shouldBe "Name.Name:void(char*)"
          argsOf(ctor) shouldBe List(1 -> "\"x\"")
          ctor.callee.isExternal.l shouldBe List(false)
          val listCtor = assignmentTo("b").argument(2).asInstanceOf[Call]
          listCtor.methodFullName shouldBe "Name.Name:void(char*)"
          argsOf(listCtor) shouldBe List(1 -> "\"y\"")
      }

      "call the copy constructor the class declares for an object of its own type" in {
          val ctor = assignmentTo("d").argument(2).asInstanceOf[Call]
          ctor.methodFullName shouldBe "Name.Name:void(Name &)"
          argsOf(ctor) shouldBe List(1 -> "a")
      }

      "construct nothing more for a value of the variable's own type" in {
          val cast = assignmentTo("c").argument(2).asInstanceOf[Call]
          cast.code shouldBe "Name(\"z\")"
          cast.methodFullName shouldBe "Name.Name:void(char*)"
          assignmentTo("e").argument(2).code shouldBe "make()"
      }
  }

  "destructors" should {
      val cpg = code("""
          |struct Base { virtual ~Base() {} };
          |struct Impl : Base { int *data; Impl() { data = new int[4]; } ~Impl() override { delete[] data; } };
          |struct Guard { Guard(); ~Guard(); };
          |void scoped() {
          |  Guard first;
          |  Guard second;
          |  for (Guard g; ;) { break; }
          |}
          |int main() {
          |  Impl *raw = new Impl;
          |  Impl *arr = new Impl[4];
          |  Base *base = new Impl;
          |  delete raw;
          |  delete[] arr;
          |  delete base;
          |  return 0;
          |}
          |""".stripMargin)
      def callIn(code: String): Call = cpg.call.codeExact(code).head

      "follow delete with the destructor call, tagged with its form" in {
          val scalar = callIn("delete raw")
          tagsOf(scalar, X2CpgDefines.AllocFormTag) shouldBe List(X2CpgDefines.AllocFormScalar)
          val List(ptr, dtor: Call) = scalar.argument.l: @unchecked
          ptr.code shouldBe "raw"
          dtor.methodFullName shouldBe "Impl.~Impl:void()"
          dtor.callee.isExternal.l shouldBe List(false)

          val array = callIn("delete[] arr")
          tagsOf(array, X2CpgDefines.AllocFormTag) shouldBe List(X2CpgDefines.AllocFormArray)
          array.argument(2).asInstanceOf[Call].methodFullName shouldBe "Impl.~Impl:void()"
      }

      "reach the subclass destructor through a virtual destructor" in {
          val dtor = callIn("delete base").argument(2).asInstanceOf[Call]
          dtor.methodFullName shouldBe "Base.~Base:void()"
          dtor.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH
          dtor.callee.fullName.toSetMutable shouldBe Set("Base.~Base:void()", "Impl.~Impl:void()")
      }

      "end a scope with its destructor calls, the last constructed first" in {
          cpg.method.nameExact("scoped").call.nameExact("~Guard").code.l shouldBe List(
            "g.~Guard()",
            "second.~Guard()",
            "first.~Guard()"
          )
      }

      "tag array allocations" in {
          tagsOf(callIn("new Impl[4]"), X2CpgDefines.AllocFormTag) shouldBe List(
            X2CpgDefines.AllocFormArray
          )
          callIn("new Impl[4]").argument.code.l shouldBe List("Impl", "4", "Impl()")
      }
  }

  "template instances" should {
      val cpg = code("""
          |template <typename T> T clampAdd(T a, T b) { return a + b; }
          |template <> int clampAdd<int>(int a, int b) { return a - b; }
          |template <typename T> struct Box {
          |  T value;
          |  T get() const { return value; }
          |};
          |int main(int argc, char **argv) {
          |  short s = clampAdd<short>(argc, 7);
          |  int t = clampAdd(argc, 1);
          |  Box<long> box;
          |  return s + t + box.get();
          |}
          |""".stripMargin)
      def callIn(code: String): Call = cpg.method.nameExact("main").call.codeExact(code).head

      "call the generic definition, keeping the instance's signature in a tag" in {
          val call = callIn("clampAdd<short>(argc, 7)")
          call.methodFullName shouldBe "clampAdd:ANY(ANY,ANY)"
          call.callee.isExternal.l shouldBe List(false)
          tagsOf(call, X2CpgDefines.TemplateInstanceTag) shouldBe List(
            "short int(short int,short int)"
          )
      }

      "call an explicit specialization by its own name" in {
          val call = callIn("clampAdd(argc, 1)")
          call.methodFullName shouldBe "clampAdd:int(int,int)"
          call.callee.isExternal.l shouldBe List(false)
          call.tag.nameExact(X2CpgDefines.TemplateInstanceTag).l shouldBe empty
      }

      "call a member of a class template instance on the template's member" in {
          val call = callIn("box.get()")
          call.callee.isExternal.l shouldBe List(false)
          call.callee.name.l shouldBe List("get")
          tagsOf(call, X2CpgDefines.TemplateInstanceTag) shouldBe List("long int()")
      }
  }

  "lambdas" should {
      val cpg = code("""
          |int main(int argc, char **argv) {
          |  int v = 0;
          |  auto add = [&v](int q) { v += q; return v; };
          |  int r = add(argc);
          |  return r + [](int a) { return a * 2; }(argc);
          |}
          |""".stripMargin)

      "call the lambda's METHOD through its closure" in {
          val call = cpg.method.nameExact("main").call.codeExact("add(argc)").head
          call.name shouldBe "anonymous_lambda_0"
          call.methodFullName shouldBe "main:int(int,char**).anonymous_lambda_0"
          call.dispatchType shouldBe DispatchTypes.STATIC_DISPATCH
          call.callee.fullName.l shouldBe List("main:int(int,char**).anonymous_lambda_0")
          call.receiver.code.l shouldBe List("add")
          call.receiver.argumentIndex.l shouldBe List(-1)
          argsOf(call) shouldBe List(1 -> "argc")
      }

      "call an immediately invoked lambda" in {
          val call =
              cpg.method.nameExact("main").call.codeExact("[](int a) { return a * 2; }(argc)").head
          call.name shouldBe "anonymous_lambda_1"
          call.callee.isExternal.l shouldBe List(false)
      }

      "give a lambda the return type CDT deduces from its body" in {
          cpg.method.nameExact("anonymous_lambda_0").methodReturn.typeFullName.l shouldBe List(
            "int"
          )
      }
  }
end CppImplicitCallTests
