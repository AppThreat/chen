package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.{AbstractPassTest, Defines}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, ModifierTypes, Operators}
import io.shiftleft.semanticcpg.language.*

class ReactFlightDOMServerNodeTest extends AbstractPassTest {

    "AST generation for ReactFlightDOMServerNode (Flow Syntax)" should {

        "handle Flow TypeAlias with 'right' property (The Crash Reproducer)" in AstFixture(
            """
              |// @flow
              |type Options = {
              |  debugChannel?: Readable | Writable | Duplex | WebSocket,
              |  environmentName?: string | (() => string),
              |  identifierPrefix?: string
              |};
              |""".stripMargin) { cpg =>
            val List(options) = cpg.typeDecl.name("Options").l
            options.fullName should endWith(":program:Options")
            options.member.name.l should contain allElementsOf List("debugChannel", "environmentName", "identifierPrefix")
            val List(idPrefix) = options.member.name("identifierPrefix").l
            idPrefix.typeFullName shouldBe Defines.String
        }

        "handle ObjectTypeAnnotation with function members" in AstFixture(
            """
              |// @flow
              |type PipeableStream = {
              |  abort(reason: mixed): void,
              |  pipe<T: Writable>(destination: T): T,
              |};
              |""".stripMargin) { cpg =>
            val List(streamType) = cpg.typeDecl.name("PipeableStream").l
            val List(abortMember) = streamType.member.name("abort").l
            abortMember.code should include("abort(reason: mixed)")
            val List(pipeMember) = streamType.member.name("pipe").l
            pipeMember.code should include("pipe<T: Writable>(destination: T)")
        }

        "handle generic functions inside object literals (renderToPipeableStream)" in AstFixture(
            """
              |// @flow
              |function renderToPipeableStream(model: ReactClientValue): PipeableStream {
              |  const request = createRequest(model);
              |  return {
              |    pipe<T: Writable>(destination: T): T {
              |      startFlowing(request, destination);
              |      return destination;
              |    },
              |    abort(reason: mixed) {
              |      abort(request, reason);
              |    },
              |  };
              |}
              |""".stripMargin) { cpg =>
            val List(renderMethod) = cpg.method.name("renderToPipeableStream").l
            val List(ret) = renderMethod.block.astChildren.isReturn.l
            val List(objLiteral) = ret.astChildren.isBlock.l
            val pipeMethods = cpg.method.name("pipe").l
            pipeMethods.size should be >= 1
            val pipe = pipeMethods.find(_.fullName.contains("renderToPipeableStream")).get
            pipe.parameter.name("destination").head.typeFullName shouldBe "T"
        }

        "handle Flow DeclareFunction with generics" in AstFixture(
            """
              |// @flow
              |declare function flushSyncFromReconciler<R>(fn: () => R): R;
              |declare function flushSyncFromReconciler(): void;
              |""".stripMargin) { cpg =>
            val methods = cpg.method.name("flushSyncFromReconciler.*").l
            methods.size shouldBe 2
        }

        "handle typeof type annotation in variable declaration" in AstFixture(
            """
              |// @flow
              |const flushSync: typeof flushSyncIsomorphic = disableLegacyMode
              |  ? flushSyncIsomorphic
              |  : flushSyncFromReconciler;
              |""".stripMargin) { cpg =>
            val List(local) = cpg.local.name("flushSync").l
            local.code shouldBe "flushSync"
        }

        "handle function parameters with nullable types and default values" in AstFixture(
            """
              |// @flow
              |function createPortal(
              |  children: ReactNodeList,
              |  container: Element | DocumentFragment,
              |  key: ?string = null,
              |): React$Portal {
              |  return createPortalImpl(children, container, null, key);
              |}
              |""".stripMargin) { cpg =>
            val List(method) = cpg.method.name("createPortal").l
            val List(keyParam) = method.parameter.name("key").l
            keyParam.index shouldBe 3
            val block = method.block
            block.astChildren.isCall.code.l.exists(_.contains("key === void 0")) shouldBe true
        }

        "handle complex AsyncIterable signatures" in AstFixture(
            """
              |// @flow
              |function decode(
              |  iterable: AsyncIterable<[string, string | File]>
              |): Thenable<T> {
              |  return getRoot(response);
              |}
              |""".stripMargin) { cpg =>
            val List(method) = cpg.method.name("decode").l
            val List(iterable) = method.parameter.name("iterable").l
            iterable.typeFullName should include ("AsyncIterable")
        }
    }
}