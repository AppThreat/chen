package io.appthreat.php2atom.querying

import io.appthreat.php2atom.astcreation.AstCreator
import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** The shapes the callsites slice reads from the PHP graph: resolved attributes and class
  * references, declared-type call names, class positions, trait use, free-function names, pipes and
  * property hooks. Each shape has a twin that must stay as it was.
  */
class CallSiteShapesTests extends PhpCode2CpgFixture:

  private def writtenNames(cpg: io.shiftleft.codepropertygraph.Cpg, kind: String): List[String] =
      cpg.tag.name(AstCreator.WrittenNameTag).value.l.map(ujson.read(_)).filter(
        _("kind").str == kind
      ).map(v => s"${v("type").str}@${v("line").num.toInt}")

  "attributes" should {
      "be annotation nodes with names resolved through use and the namespace, on every target" in {
          val cpg = code("""<?php
              |namespace App;
              |use Doctrine\ORM\Mapping as ORM;
              |use Symfony\Component\Routing\Attribute\Route;
              |#[Route('/blog')]
              |class Blog {
              |    #[ORM\Column]
              |    private int $id = 0;
              |    #[ORM\Const1]
              |    const A = 1;
              |    #[Route('/x')]
              |    public function idx(#[ORM\Param] $p): void {}
              |}
              |#[ORM\Kind]
              |enum Suit {
              |    #[ORM\Case1]
              |    case Hearts;
              |}
              |""".stripMargin)
          cpg.annotation.fullName.l.sorted shouldBe List(
            "Doctrine\\ORM\\Mapping\\Case1",
            "Doctrine\\ORM\\Mapping\\Column",
            "Doctrine\\ORM\\Mapping\\Const1",
            "Doctrine\\ORM\\Mapping\\Kind",
            "Doctrine\\ORM\\Mapping\\Param",
            "Symfony\\Component\\Routing\\Attribute\\Route",
            "Symfony\\Component\\Routing\\Attribute\\Route"
          )
          cpg.typeDecl.name("Blog").annotation.lineNumber.l shouldBe List(5)
          cpg.member.name("A").annotation.fullName.l shouldBe List("Doctrine\\ORM\\Mapping\\Const1")
          cpg.member.name("Hearts").annotation.fullName.l shouldBe
              List("Doctrine\\ORM\\Mapping\\Case1")
      }

      "name a project class when nothing is imported (twin)" in {
          val cpg = code("""<?php
              |namespace App;
              |#[Route('/blog')]
              |class Blog {}
              |""".stripMargin)
          cpg.annotation.fullName.l shouldBe List("App\\Route")
      }
  }

  "class references" should {
      "be type references that carry the resolved class" in {
          val cpg = code("""<?php
              |namespace App;
              |use Doctrine\DBAL\Types\Types;
              |function f($a) {
              |    $x = Types::INTEGER;
              |    $y = Types::class;
              |    $z = Types::$p;
              |    $a instanceof Types;
              |    try { g(); } catch (\Exception | Err $e) { }
              |}
              |""".stripMargin)
          cpg.typeRef.typeFullName.l.sorted shouldBe List(
            "App\\Err",
            "Doctrine\\DBAL\\Types\\Types",
            "Doctrine\\DBAL\\Types\\Types",
            "Doctrine\\DBAL\\Types\\Types",
            "Doctrine\\DBAL\\Types\\Types",
            "Exception"
          )
          val constRef = cpg.typeRef.where(_.astParent.isCall.code(".*::INTEGER")).l
          constRef.map(_.lineNumber) shouldBe List(Some(5))
      }

      "leave self, static, parent and variables alone (twin)" in {
          val cpg = code("""<?php
              |class A extends B {
              |    function f($o) {
              |        $a = self::X;
              |        $b = static::Y;
              |        $c = parent::Z;
              |        $d = $o::W;
              |        $o instanceof self;
              |    }
              |}
              |""".stripMargin)
          cpg.typeRef.l shouldBe Nil
      }
  }

  "instance calls" should {
      "be named after the declared class of a parameter, nullable included" in {
          val cpg = code("""<?php
              |namespace App;
              |use Psr\Log\LoggerInterface;
              |function f(LoggerInterface $log, ?Mailer $m, Foo|null $n) {
              |    $log->info('x');
              |    $m?->send();
              |    $n->go();
              |}
              |""".stripMargin)
          cpg.call.name("info|send|go").methodFullName.l shouldBe List(
            "Psr\\Log\\LoggerInterface->info",
            "App\\Mailer->send",
            "App\\Foo->go"
          )
      }

      "leave a parameter that is written, a union and a scalar unresolved (twin)" in {
          val cpg = code("""<?php
              |function f(Foo $a, Foo|Bar $u, int $i, Foo $r) {
              |    $a = other();
              |    $a->w();
              |    $u->x();
              |    $i->y();
              |    foo($r);
              |    $r = 1;
              |    $r->z();
              |}
              |""".stripMargin)
          cpg.call.name("w|x|y|z").methodFullName.l.foreach(_ should startWith(
            "<unresolvedNamespace>"
          ))
      }

      "be named after new, written once, or in place" in {
          val cpg = code("""<?php
              |namespace App;
              |function f() {
              |    $x = new Qux();
              |    $x->go();
              |    (new Other)->run();
              |}
              |""".stripMargin)
          cpg.call.name("go|run").methodFullName.l shouldBe List("App\\Qux->go", "App\\Other->run")
      }

      "stay unresolved for a reassigned variable, a by-reference capture and a loop target (twin)" in {
          val cpg = code("""<?php
              |function f($list) {
              |    $a = new A(); $a = new B();
              |    $a->one();
              |    $b = new A();
              |    $g = function () use (&$b) { $b = 1; };
              |    $b->two();
              |    $c = new A();
              |    foreach ($list as $c) { }
              |    $c->three();
              |}
              |""".stripMargin)
          cpg.call.name("one|two|three").methodFullName.l.foreach(
            _ should startWith("<unresolvedNamespace>")
          )
      }

      "be named through a typed or promoted property of the enclosing class" in {
          val cpg = code("""<?php
              |namespace App;
              |class C {
              |    private Cache $cache;
              |    private $untyped;
              |    public function __construct(private Logger $log, string $s) {}
              |    public function f() {
              |        $this->cache->get();
              |        $this->log->info();
              |        $this->untyped->nope();
              |    }
              |}
              |""".stripMargin)
          cpg.call.name("get").methodFullName.l shouldBe List("App\\Cache->get")
          cpg.call.name("info").methodFullName.l shouldBe List("App\\Logger->info")
          cpg.call.name("nope").methodFullName.l.foreach(_ should startWith(
            "<unresolvedNamespace>"
          ))
      }

      "be named inside a closure that inherits a variable it never writes" in {
          val cpg = code("""<?php
              |function f(Foo $a, Foo $b) {
              |    $g = function () use ($a, $b) { $b = 1; $a->one(); $b->two(); };
              |    $h = fn() => $a->three();
              |}
              |""".stripMargin)
          cpg.call.name("one").methodFullName.l shouldBe List("Foo->one")
          cpg.call.name("two").methodFullName.l.foreach(_ should startWith("<unresolvedNamespace>"))
          cpg.call.name("three").methodFullName.l shouldBe List("Foo->three")
      }
  }

  "classes" should {
      "sit at their name, not at their first attribute" in {
          val cpg = code("""<?php
              |namespace App;
              |#[Route('/blog')]
              |#[Other]
              |final class Blog extends Base implements \Countable {
              |}
              |""".stripMargin)
          cpg.typeDecl.name("Blog").lineNumber.l shouldBe List(5)
          writtenNames(cpg, "extends") shouldBe List("App\\Base@5")
          writtenNames(cpg, "implements") shouldBe List("Countable@5")
      }

      "lower trait use as heritage at each trait name" in {
          val cpg = code("""<?php
              |namespace App;
              |class C {
              |    use Greets, \Vendor\Logs;
              |    use Other;
              |}
              |""".stripMargin)
          writtenNames(cpg, "use") shouldBe List("App\\Greets@4", "Vendor\\Logs@4", "App\\Other@5")
          cpg.typeDecl.name("C").inheritsFromTypeFullName.l shouldBe
              List("App\\Greets", "Vendor\\Logs", "App\\Other")
      }

      "write each member of a declared type with its own line" in {
          val cpg = code("""<?php
              |namespace App;
              |class C {
              |    private ?Cache $c;
              |    const string K = 'x';
              |    public function f(
              |        A|B $u,
              |        int $i
              |    ): ?Out {}
              |}
              |""".stripMargin)
          writtenNames(cpg, "decltype").sorted shouldBe
              List("App\\A@7", "App\\B@7", "App\\Cache@4", "App\\Out@9")
      }
  }

  "function calls" should {
      "be named by their namespace, also inside a class" in {
          val cpg = code("""<?php
              |namespace App;
              |use function Foo\helper;
              |class C {
              |    function m() {
              |        local();
              |        helper();
              |        \Abs\fn1();
              |        abs(1);
              |    }
              |}
              |""".stripMargin)
          cpg.call.name("local").methodFullName.l shouldBe List("App\\local")
          cpg.call.name("helper").methodFullName.l shouldBe List("Foo\\helper")
          cpg.call.name("fn1").methodFullName.l shouldBe List("Abs\\fn1")
          cpg.call.name("abs").methodFullName.l shouldBe List("abs")
      }

      "carry the global function PHP falls back to for an unqualified name" in {
          val cpg = code("""<?php
              |namespace App;
              |function f() { collect(); \Foo\bar(); }
              |""".stripMargin)
          cpg.call.name("collect").dynamicTypeHintFullName.l shouldBe List("collect")
          cpg.call.name("bar").dynamicTypeHintFullName.l shouldBe Nil
      }
  }

  "the pipe operator" should {
      "lower to nested calls, every callee named" in {
          val cpg = code("""<?php
              |namespace App;
              |use Ramsey\Uuid\Uuid;
              |$r = Uuid::uuid4() |> strval(...) |> (new Logger(...)) |> abs(...);
              |""".stripMargin)
          cpg.call.name("uuid4").methodFullName.l shouldBe List("Ramsey\\Uuid\\Uuid::uuid4")
          // unqualified in a namespace: the namespace's function, else the global one
          cpg.call.name("strval").methodFullName.l shouldBe List("App\\strval")
          cpg.call.name("strval").dynamicTypeHintFullName.l shouldBe List("strval")
          cpg.call.name("abs").methodFullName.l shouldBe List("abs")
          cpg.call.name("__construct").methodFullName.l shouldBe List("App\\Logger->__construct")
          // the left side is the call's argument
          cpg.call.name("strval").argument.argumentIndex(1).code.l shouldBe List(
            "Ramsey\\Uuid\\Uuid::uuid4()"
          )
      }
  }

  "a typed call" should {
      "carry the position of its method name, also in a chain written across lines" in {
          val cpg = code("""<?php
              |function f(Schema $schema, $other) {
              |    $schema
              |        ->string();
              |    $schema->array();
              |    $other->none();
              |}
              |""".stripMargin)
          val at = cpg.tag.name(AstCreator.NamePositionTag).value.l.map { v =>
            val json = ujson.read(v)
            (json("line").num.toInt, json("col").num.toInt)
          }
          // `->string()` on line 4 (the name after 8 spaces and `->`), `array` on line 5
          at.sorted shouldBe List((4, 10), (5, 13))
          cpg.call.name("none").tag.name(AstCreator.NamePositionTag).l shouldBe Nil
      }

      "put the init call of new at the class name" in {
          val cpg = code("""<?php
              |$x = new
              |    Foo();
              |""".stripMargin)
          val init = cpg.call.name("__construct").l
          init.map(c => (c.lineNumber.get.intValue, c.columnNumber.get.intValue)) shouldBe List((
            3,
            4
          ))
      }
  }

  "a parameter's default value" should {
      "tag the classes it names, and a scalar default tags none (twin)" in {
          val cpg = code("""<?php
              |namespace App;
              |function f(
              |    int $a = Flag::LIMIT,
              |    string $b = Flag::class,
              |    $c = new Gadget(1),
              |    $d = 3,
              |    $e = self::X
              |) {}
              |""".stripMargin)
          val tags = cpg.tag.name(AstCreator.WrittenNameTag).value.l.map(ujson.read(_))
              .filter(v => Set("ref", "new").contains(v("kind").str))
              .map(v => (v("kind").str, v("type").str, v("member").str, v("line").num.toInt))
          tags.sorted shouldBe List(
            ("new", "App\\Gadget", "", 6),
            ("ref", "App\\Flag", "LIMIT", 4),
            ("ref", "App\\Flag", "class", 5)
          )
      }
  }

  "anonymous classes" should {
      "be type declarations with their heritage and body, and the new of them" in {
          val cpg = code("""<?php
              |namespace App;
              |use Illuminate\Database\Migrations\Migration;
              |return new class extends Migration {
              |    public function up(Blueprint $table) { $table->id(); }
              |};
              |""".stripMargin)
          val anon = cpg.typeDecl.name("class@anonymous.*").l
          anon.map(_.inheritsFromTypeFullName) shouldBe List(
            List("Illuminate\\Database\\Migrations\\Migration")
          )
          cpg.call.name("id").methodFullName.l shouldBe List("App\\Blueprint->id")
          cpg.method.name("up").l.size shouldBe 1
          cpg.call.name("__construct").methodFullName.l.head should startWith(
            "App\\class@anonymous"
          )
          writtenNames(cpg, "extends") shouldBe List(
            "Illuminate\\Database\\Migrations\\Migration@4"
          )
      }
  }

  "calls the frontend makes up" should {
      "carry the synthetic tag, and a call that is written does not" in {
          val cpg = code("""<?php
              |function f($xs, $a) {
              |    $a[] = 1;
              |    foreach ($xs as $x) { abs($x); }
              |}
              |""".stripMargin)
          val tagged = cpg.tag.name(AstCreator.SyntheticCallTag)._taggedByIn.collect {
              case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c.name
          }.l
          // `current` twice: the foreach's item assignment is copied for its update step
          tagged.sorted shouldBe List("array_push", "current", "current", "is_null", "next")
          cpg.call.name("abs").tag.name(AstCreator.SyntheticCallTag).l shouldBe Nil
      }
  }

  "property hooks" should {
      "be methods of their class, so their calls have an enclosing method" in {
          val cpg = code("""<?php
              |namespace App;
              |class U {
              |    public string $name { get => $this->n; set { $this->n = strtoupper($value); } }
              |    public string $full { get => Uuid::uuid4()->toString(); }
              |}
              |""".stripMargin)
          cpg.method.name("\\$name::get|\\$name::set|\\$full::get").fullName.l.sorted shouldBe
              List("App\\U->$full::get", "App\\U->$name::get", "App\\U->$name::set")
          cpg.call.name("strtoupper").method.name.l shouldBe List("$name::set")
          cpg.call.name("uuid4").method.name.l shouldBe List("$full::get")
          cpg.call.l.foreach(_.method should not be null)
      }
  }
end CallSiteShapesTests
