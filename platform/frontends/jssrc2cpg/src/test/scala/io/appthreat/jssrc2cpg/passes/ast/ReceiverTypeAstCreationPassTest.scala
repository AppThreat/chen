package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.AbstractPassTest
import io.shiftleft.semanticcpg.language.*

/** The receiver of a member call on a member read or on a call result, typed from a TypeScript 6
  * type map (no span map), and the type references of a file as `callsites-typeref` tags. The
  * committed astgen output (`receiver-types/`, see its README) carries the type map, so astgen is
  * not invoked.
  */
class ReceiverTypeAstCreationPassTest extends AbstractPassTest:

  /** The type of the temporary that holds the receiver of the call named `name`. */
  private def receiverTypes(cpg: io.shiftleft.codepropertygraph.Cpg, name: String): List[String] =
      cpg.call.nameExact(name).argument(0).isIdentifier.typeFullName.l

  "Receivers of member calls" should {
      "take the type of a field read from the type map at the field's name" in AstJsonFixture(
        "receiver-types"
      ) { cpg =>
          // `this.isSubmitting.set(...)`, twice: the field holds `signal(false)`
          receiverTypes(cpg, "set") shouldBe List(
            "@angular/core:WritableSignal",
            "@angular/core:WritableSignal"
          )
      }

      "take the type of a call result from the callee's return" in AstJsonFixture(
        "receiver-types"
      ) { cpg =>
          // `this.feed.get("a").pipe()`
          receiverTypes(cpg, "pipe") shouldBe List("Observable")
      }

      "look through a non-null assertion and an optional member read" in AstJsonFixture(
        "receiver-types"
      ) { cpg =>
        // `this.feed.items$!.subscribe()` and `this.sub?.unsubscribe()` (`Subscription | null`)
        receiverTypes(cpg, "subscribe") shouldBe List("Observable")
        receiverTypes(cpg, "unsubscribe") shouldBe List("Subscription")
      }
  }

  "Type references" should {
      "be tagged on the file's program method with their name and position" in AstJsonFixture(
        "receiver-types"
      ) { cpg =>
        // lines are 1-based and columns 0-based, as on every other node
        val refs = cpg.method.nameExact(":program").tag.nameExact("callsites-typeref").value.l
            .map(ujson.read(_))
            .map(t => (t("name").str, t("line").num.toInt, t("column").num.toInt))
        refs.sorted shouldBe List(
          ("Feed", 15, 37),
          ("Feed", 29, 9),
          ("Observable", 5, 11),
          ("Observable", 6, 19),
          ("Observable", 7, 37),
          ("Subscription", 13, 15)
        )
      }
  }
end ReceiverTypeAstCreationPassTest
