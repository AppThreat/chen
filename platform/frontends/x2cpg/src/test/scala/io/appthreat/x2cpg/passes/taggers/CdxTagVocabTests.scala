package io.appthreat.x2cpg.passes.taggers

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Pins chen's description-tag fallback to cdxgen's `extractTags`: every expected list below was
  * produced by running cdxgen's `extractTags({ description: d }, "all")` from
  * `lib/stages/postgen/annotator.js` against the same `data/component-tags.json` this repo vendors
  * as a resource. If chen and cdxgen ever disagree about a description, one of these cases will
  * fail.
  */
class CdxTagVocabTests extends AnyWordSpec with Matchers:

  private val oracle = List(
    // (description, cdxgen extractTags output)
    "A robust authentication and authorization library" -> Nil,
    "Python HTTP for Humans."                           -> List("http"),
    "AI toolkit for building LLM applications with RAG" -> List("llm"),
    "Web framework built on top of asyncio, with templates and ORM" -> List(
      "framework",
      "templates"
    ),
    "The Werkzeug WSGI HTTP Utility Library for Python"         -> List("http", "wsgi"),
    "A modern, fast (high-performance) web framework"           -> List("web"),
    "Command line tool to manage databases and run migrations"  -> Nil,
    "Machine learning library for computer vision and NLP"      -> Nil,
    "Payment processing SDK with support for Stripe and PayPal" -> List("stripe"),
    "Logging made easy"                                         -> Nil,
    "A logical framework for log analysis"                      -> List("framework", "log"),
    "This package does nothing useful"                          -> Nil,
    "Tools for developers and testers"                          -> Nil,
    "GraphQL server and gRPC client support"                    -> List("grpc")
  )

  "CdxTagVocab" should {

      "match cdxgen's extractTags output exactly for pinned descriptions" in {
          oracle.foreach { case (description, expected) =>
              withClue(s"description: '$description':") {
                  CdxTagVocab.extractDescTags(description) shouldBe expected
              }
          }
      }

      "not match a vocabulary entry inside a longer word (chen's old leading-only rule did)" in {
          // old rule: desc.contains(" auth") matched "authentication"; the vendored
          // boundary rule must not produce anything here
          CdxTagVocab.extractDescTags("Authentication utilities for authors") shouldBe empty
          // same for `log` inside `logic`
          CdxTagVocab.extractDescTags("Logic programming toolkit") shouldBe empty
      }

      "match a vocabulary entry as a whole word at the end of a sentence" in {
          CdxTagVocab.extractDescTags("A toolkit for building web apps with auth.") should contain(
            "auth"
          )
      }

      "carry the cdxgen-merged vocabulary entries chen's old file lacked" in {
          val vocab = CdxTagVocab.descriptionTags
          List("ai", "ml", "framework", "http", "grpc", "graphql", "wsgi", "asgi", "llm", "mcp")
              .foreach(tag => vocab should contain(tag))
      }

      "deduplicate vocabulary matches the way cdxgen's JS Set does" in {
          // the vendored file contains `redis` (and `mvc`) twice, as does cdxgen's
          CdxTagVocab.extractDescTags("A redis client for redis clusters") shouldBe List("redis")
      }

      "yield no tags for an empty description" in {
          CdxTagVocab.extractDescTags("") shouldBe empty
      }
  }
end CdxTagVocabTests
