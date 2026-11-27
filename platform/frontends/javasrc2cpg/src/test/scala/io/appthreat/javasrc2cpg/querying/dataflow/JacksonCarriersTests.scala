package io.appthreat.javasrc2cpg.querying.dataflow

import io.appthreat.javasrc2cpg.testfixtures.JavaDataflowFixture
import io.appthreat.dataflowengineoss.language.*
import io.shiftleft.semanticcpg.language.*

/** The Jackson carriers in `JavaFrameworkSemantics.Carriers` must keep taint flowing from the
  * deserialisation source string to the object it produces, in both Jackson majors.
  *
  * Why a plain flow test is not enough on its own: the query engine crosses an undeclared external
  * call permissively - an opaque callee's arguments taint its result (`TaskCreator`
  * .tasksForUnresolvedOutArgs) - so a flow through an unlisted `readValue` overload passes by
  * accident. The declared carrier is what makes the pass-through explicit and summary-safe; the
  * tripwire for removing an entry is the explicit enumeration in `LanguageScopedSemanticsTests`,
  * which fails as soon as one of these full names disappears from the defaults.
  */
class JacksonCarriersTests extends JavaDataflowFixture:

  override val code =
      """
      |package com.example;
      |
      |import tools.jackson.databind.ObjectMapper;
      |import tools.jackson.databind.json.JsonMapper;
      |
      |public class Readers {
      |    public Item viaJackson3ObjectMapper(String q) throws Exception {
      |        ObjectMapper mapper = new ObjectMapper();
      |        return mapper.readValue(q, Item.class);
      |    }
      |
      |    public Item viaJackson3JsonMapper(String q) throws Exception {
      |        JsonMapper mapper = new JsonMapper();
      |        return mapper.readValue(q, Item.class);
      |    }
      |
      |    public Item viaJackson2ObjectMapper(String q) throws Exception {
      |        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
      |        return mapper.readValue(q, Item.class);
      |    }
      |
      |    public Item viaLocalHelper(String q) {
      |        return readValue(q, Item.class);
      |    }
      |
      |    Item readValue(String q, Class<?> type) { return new Item(); }
      |}
      |
      |class Item {
      |}
      |""".stripMargin

  private def flowCount(methodName: String): Int =
    def src = cpg.method(methodName).parameter.name("q")
    def snk = cpg.method(methodName).methodReturn.toReturn
    snk.reachableByFlows(src).size

  behavior of "The Jackson carriers"

  it should "carry the source argument through a Jackson 3 ObjectMapper.readValue to the return" in {
      flowCount("viaJackson3ObjectMapper") should not be 0
  }

  it should "carry the source argument through a Jackson 3 JsonMapper.readValue to the return" in {
      flowCount("viaJackson3JsonMapper") should not be 0
  }

  it should "carry the source argument through a Jackson 2 ObjectMapper.readValue to the return" in {
      flowCount("viaJackson2ObjectMapper") should not be 0
  }

  it should "not invent a flow through a local helper that ignores its argument" in {
      // `readValue` here is the project's own method with a body that drops its first argument;
      // no carrier entry matches it (the carriers are fully qualified to the Jackson classes), so
      // the engine descends into the body and finds nothing.
      flowCount("viaLocalHelper") shouldBe 0
  }
end JacksonCarriersTests
