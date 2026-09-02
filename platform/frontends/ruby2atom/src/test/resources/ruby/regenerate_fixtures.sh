#!/usr/bin/env bash
# Regenerates the committed rbastgen JSON for every fixture .rb in this directory.
# Usage: ./regenerate_fixtures.sh /path/to/ruby_ast_gen [ruby2atom-src-test-resources/ruby]
#
# Requires a ruby_ast_gen checkout at the version recorded in README.md, with `bundle exec`
# able to resolve its Gemfile.
set -euo pipefail

AST_GEN_REPO="${1:?usage: regenerate_fixtures.sh /path/to/ruby_ast_gen [target-dir]}"
TARGET_DIR="${2:-$(cd "$(dirname "$0")" && pwd)}"

WORK_DIR="$(mktemp -d)"
WORK_DIR_TRUNCATED="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR" "$WORK_DIR_TRUNCATED"' EXIT

pushd "$AST_GEN_REPO" >/dev/null

# chen invokes the generator in directory mode (`rbastgen -i <dir> -o <out>`), so the fixtures
# must be generated that way too: in single-file mode `rel_file_path` is the basename, which
# would silently rewrite `models/user.rb` to `user.rb` and break require resolution (the
# generator's plan 03 §5 fix). The truncation fixture needs a second run at --max-depth 3.
bundle exec ruby exe/ruby_ast_gen -i "$TARGET_DIR" -o "$WORK_DIR" -e ZZZNOMATCH
bundle exec ruby exe/ruby_ast_gen -i "$TARGET_DIR" -o "$WORK_DIR_TRUNCATED" -e ZZZNOMATCH --max-depth 3
cp "$WORK_DIR_TRUNCATED/nested/truncated.rb.json" "$WORK_DIR/nested/truncated.rb.json"

popd >/dev/null

# rbastgen writes <name>.rb.json; overwrite the committed copies in place.
find "$WORK_DIR" -name '*.rb.json' -print0 |
  while IFS= read -r -d '' generated; do
    rel="${generated#"$WORK_DIR"/}"
    cp "$generated" "$TARGET_DIR/$rel"
  done

echo "Regenerated fixtures under $TARGET_DIR"
