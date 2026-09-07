package io.appthreat.x2cpg.passes.taggers

import io.circe.parser.*

import scala.io.Source
import scala.util.Using

/** The description-tag vocabulary and matcher used by [[CdxPass]]'s fallback path, vendored from
  * cdxgen's `data/component-tags.json` so that chen and cdxgen cannot disagree about the same
  * component description.
  *
  * Matching ports cdxgen's `extractTags` (lib/stages/postgen/annotator.js): the lowercased
  * description must contain the tag delimited on both sides - `" tag "` or `" tag."` - and the
  * result is sorted lexicographically, exactly like cdxgen's `Array.from(tags).sort()`. chen's old
  * `tags-vocab.txt` rule (`desc.contains(" tag")`, leading boundary only) matched e.g. `auth`
  * inside `author`; this one does not.
  *
  * NB: cdxgen's `extractTags` has a second, "stemmed" check whose `stemmedDesc` is derived from the
  * tag itself rather than from the description. That check can never fire (the derived string has
  * no leading space), so it is not reproduced here.
  */
object CdxTagVocab:

  private val ResourcePath = "component-tags.json"

  private lazy val vocab: List[String] =
      Using(Source.fromResource(ResourcePath))(_.mkString).toOption.toList.flatMap { jsonStr =>
          parse(jsonStr) match
            case Right(json) =>
                json.hcursor.downField("description").downField("all").as[List[String]].getOrElse(
                  List.empty
                )
            case Left(_) =>
                List.empty
      }

  /** Tags whose vocabulary entry matches the given description, in cdxgen's order (lexicographic).
    * The vocabulary contains a few duplicate entries; cdxgen deduplicates through a JS `Set` before
    * sorting, so the same tag must not appear twice here. Empty input yields no tags, matching
    * cdxgen's `component?.description` guard.
    */
  def extractDescTags(description: String): List[String] =
      if description == null || description.isEmpty then List.empty
      else
        val desc = description.toLowerCase
        vocab.filter(tag => desc.contains(s" $tag ") || desc.contains(s" $tag.")).distinct.sorted

  /** The vendored vocabulary, for tests and diagnostics. */
  def descriptionTags: List[String] = vocab
end CdxTagVocab
