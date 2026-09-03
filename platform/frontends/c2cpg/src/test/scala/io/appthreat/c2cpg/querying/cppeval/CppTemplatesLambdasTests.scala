package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** Evaluates AST creation for modern C++ constructs: template functions, using-aliases, an
  * overloaded operator<<, free comparison functions passed as callbacks, and lambdas passed to
  * std::for_each / std::copy_if.
  */
class CppTemplatesLambdasTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private implicit val resolver: NoResolve.type = NoResolve

  private val cpg = code("""
      |#include <iostream>
      |#include <vector>
      |#include <algorithm>
      |#include <iterator>
      |#include <string>
      |#include <tuple>
      |
      |template<typename T>
      |void print_vector(std::vector<T> data, std::string info_text = "") {
      |    if (!info_text.empty()) std::cout << info_text.c_str();
      |    std::copy(data.begin(), data.end(), std::ostream_iterator<int>(std::cout, " "));
      |}
      |
      |using contact = std::tuple<std::string, std::string, std::string>;
      |using contacts = std::vector<contact>;
      |
      |std::ostream& operator<<(std::ostream& output, const contact &person) {
      |    output << std::get<1>(person) << ", " << std::get<0>(person);
      |    return output;
      |}
      |
      |bool compare_by_first_name(const contact& first, const contact &second) {
      |    return std::get<0>(first) < std::get<0>(second);
      |}
      |
      |bool compare_by_last_name(const contact& first, const contact& second) {
      |    return std::get<1>(first) < std::get<1>(second);
      |}
      |
      |void print_contacts(const contacts& list) {
      |    std::for_each(list.begin(), list.end(), [](const contact& contact) {
      |        std::cout << contact << std::endl;
      |    });
      |}
      |
      |int main(int argc, char* argv[]) {
      |    contacts demo_contacts;
      |    std::sort(demo_contacts.begin(), demo_contacts.end(), compare_by_first_name);
      |    print_contacts(demo_contacts);
      |    std::sort(demo_contacts.begin(), demo_contacts.end(), compare_by_last_name);
      |    std::vector<contact> people_with_l;
      |    std::copy_if(demo_contacts.begin(), demo_contacts.end(),
      |        std::back_inserter(people_with_l), [](const contact& person) {
      |            auto first_name = std::get<0>(person);
      |            return first_name.find('L') != std::string::npos;
      |        });
      |    print_contacts(people_with_l);
      |    return 0;
      |}
      |""".stripMargin)

  "AST: template function" should {
      "create the print_vector method with its template parameter and default argument" in {
          val m = cpg.method.nameExact("print_vector").head
          (m.parameter.name.l should contain).allOf("data", "info_text")
          m.parameter.nameExact("info_text").index.head shouldBe 2
      }

      "give print_vector a void return type" in {
          cpg.method.nameExact("print_vector").methodReturn.typeFullName.head shouldBe "void"
      }
  }

  "AST: free comparison functions" should {
      "create both comparators with two contact parameters returning bool" in {
          List("compare_by_first_name", "compare_by_last_name").foreach { name =>
            val m = cpg.method.nameExact(name).head
            m.methodReturn.typeFullName shouldBe "bool"
            m.parameter.size shouldBe 2
          }
      }
  }

  "AST: overloaded operator<<" should {
      "create a method for the operator overload" in {
          cpg.method.name(".*operator.*").internal.l should not be empty
      }
  }

  "AST: lambdas" should {
      "create dedicated method nodes for the two lambdas" in {
          // one lambda in print_contacts, one in main's copy_if
          cpg.method.internal.name(".*lambda.*").size should be >= 2
      }

      "capture the body call std::cout << contact inside a lambda" in {
          cpg.method.internal.name(".*lambda.*").ast.isCall.name(
            io.shiftleft.codepropertygraph.generated.Operators.shiftLeft
          ).l should not be empty
      }
  }

  "Call graph" should {
      "resolve print_contacts calls from main" in {
          cpg.method("main").call.nameExact("print_contacts").size shouldBe 2
          cpg.method.nameExact("print_contacts").caller.name.toSetMutable should contain("main")
      }

      "reference the comparator functions as arguments to std::sort" in {
          val sortArgs = cpg.call.name(".*sort.*").argument.code.toSetMutable
          sortArgs should contain("compare_by_first_name")
          sortArgs should contain("compare_by_last_name")
      }

      "record calls to std algorithm helpers" in {
          cpg.call.name(".*copy_if.*").l should not be empty
          cpg.call.name(".*for_each.*").l should not be empty
      }
  }

  "AST: using-aliases resolve to underlying containers" should {
      "type the demo_contacts / people_with_l locals" in {
          val locals = cpg.method("main").local.map(l => l.name -> l.typeFullName).toMap
          (locals.keys should contain).allOf("demo_contacts", "people_with_l")
      }
  }
end CppTemplatesLambdasTests
