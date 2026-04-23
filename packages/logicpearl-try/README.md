# @logicpearl/try

Kick the tires on [LogicPearl](https://logicpearl.com) in one command. No setup, no API keys, no config — the package ships with a real compiled Wasm artifact and five real captured Claude Sonnet 4.5 responses to the same input.

```bash
npx @logicpearl/try
```

You get a deterministic refund verdict in under a millisecond. Same input → same bitmask → every run.

## The demo

```bash
# The default — evaluate the shipped refund-eligibility artifact
# against a day-30 changed-mind boundary case.
npx @logicpearl/try

# Compare the artifact against 5 real captured Claude Sonnet 4.5 runs.
# (Ships with the captures — no API key needed.)
npx @logicpearl/try --explain

# Reproduce those captures live against your own key.
ANTHROPIC_API_KEY=sk-ant-... npx @logicpearl/try --explain --live

# Run the 3-stage pipeline on a plain-English customer message.
npx @logicpearl/try --from-text "I bought this a month ago and want a refund"

# Run that pipeline 5 times to see which stages vary and which stay identical.
npx @logicpearl/try --from-text "..." --prove-it
```

## Flags

| Flag | What it does |
|---|---|
| `--facts '{...}'` | Evaluate your own feature vector |
| `--facts-file <path>` | Load the facts from a JSON file |
| `--artifact <path-or-url>` | Use a different compiled artifact |
| `--describe` | Print the feature + rule schema only |
| `--explain` | Side-by-side vs 5 pre-captured LLM runs |
| `--live` | Call the LLM now (needs `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`) |
| `--from-text "<prose>"` | 3-stage pipeline: LLM extract → LogicPearl decide → LLM verbalize |
| `--prove-it` | Run the pipeline 5× and report stage variance |
| `--json` | Machine-readable output |

## What's in the package

- A compiled refund-eligibility artifact (8 KB Wasm, 5 learned rules, 8 features including a string-categorical)
- `captures/claude-sonnet-5-runs.json` — five real API responses, timestamps, prompt hash
- `captures/policy.md` — the policy text the LLM was given
- `captures/prompt.txt` — the exact prompt template

Everything in `captures/` is reproducible: pass `CAPTURE_MODEL=claude-sonnet-4-5 ANTHROPIC_API_KEY=... node scripts/capture_llm_runs.mjs` (in the repo) to regenerate them.

## What's next

- [`@logicpearl/mcp`](https://www.npmjs.com/package/@logicpearl/mcp) — one-command MCP server install for Claude Desktop + Cursor
- [`@logicpearl/browser`](https://www.npmjs.com/package/@logicpearl/browser) — `loadArtifact()` + `evaluate()` in the browser or worker
- [Docs](https://logicpearl.com/quickstart) | [Source](https://github.com/LogicPearlHQ/logicpearl)

## License

MIT
