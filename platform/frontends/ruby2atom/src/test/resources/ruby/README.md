# ruby2atom test fixtures

Each fixture is a pair: `<name>.rb` (Ruby source) and `<name>.rb.json` (the exact JSON that
`rbastgen` emits for it). The JSON is **generated, never hand-written**, so the tests exercise the
exact bytes chen receives from the generator.

Provenance of the committed JSON:

- Repo: `ruby_ast_gen` branch `main`, commit `a68aaf1`, version **2.1.0**
  (`bundle exec ruby exe/ruby_ast_gen --version` if in doubt).
- Command: `bundle exec ruby exe/ruby_ast_gen -i <resources dir> -o <out dir> -e ZZZNOMATCH`
  (`-e ZZZNOMATCH` matches nothing, i.e. disables exclusion).
- Exception: `nested/truncated.rb.json` was generated with `--max-depth 3` to produce the
  documented depth-truncated node shape (`{type, meta_data, nested, truncated}`); all other
  fixtures use the default depth.

To regenerate every JSON here (run from a ruby_ast_gen checkout at the commit above):

```bash
./regenerate_fixtures.sh /path/to/ruby_ast_gen
```

Note: the tests ingest the committed JSON rather than invoking `rbastgen` at test time, because
the `rbastgen` binary on a developer's PATH may be an older released gem (e.g. 1.3.0) that emits
a pre-v2 JSON contract without the node types and syntax facts these tests pin.
