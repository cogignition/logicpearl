# @logicpearl/mcp

A Model Context Protocol (MCP) server that exposes [LogicPearl](https://logicpearl.com) — the deterministic decision primitive — to Claude Desktop, Cursor, and any other MCP-compatible host. One command installs it.

```bash
npx @logicpearl/mcp install
```

That writes the server entry into each host's MCP config with a timestamped backup. Relaunch the host, and every chat has three new tools.

## Tools

| Tool | What it does |
|---|---|
| `logicpearl_evaluate` | Run a feature vector through the compiled artifact. Returns verdict, fired rules, counterfactual hints, latency, and a replayable bitmask. |
| `logicpearl_describe_artifact` | Return the feature schema, allowed string codes, actions, rules, and an optional extraction-prompt template. |
| `logicpearl_list_rules` | Enumerate every rule with id, action, label, features, and counterfactual hint. |

Every call is deterministic — same facts in, same bitmask out, every time.

## Install

```bash
# Both Claude Desktop and Cursor at once
npx @logicpearl/mcp install

# Just one host
npx @logicpearl/mcp install --host claude
npx @logicpearl/mcp install --host cursor

# Preview the config diff without writing
npx @logicpearl/mcp install --dry-run
```

Existing config files are copied to `<config>.<timestamp>.bak` before any write.

## Manual setup

If you use a host that isn't Claude Desktop or Cursor, add this to its `mcp.json`:

```json
{
  "mcpServers": {
    "logicpearl": {
      "command": "npx",
      "args": ["-y", "@logicpearl/mcp", "start"]
    }
  }
}
```

Pass `--artifact <url-or-path>` after `start` to override the default artifact with your own.

## Run the server directly

```bash
# Foreground, stdio transport — useful for testing with MCP Inspector
npx @logicpearl/mcp start

# Or plug into MCP Inspector
npx @modelcontextprotocol/inspector npx @logicpearl/mcp start
```

## What ships

A default refund-eligibility artifact (8 features including a string-categorical, 5 learned rules, 8 KB Wasm). Pass `--artifact` to swap in your own compiled LogicPearl bundle.

## Security posture (v1)

- stdio transport only — the host spawns the server as a child process
- No server-side auth (stdio already gates access via the host)
- No artifact-signature verification yet
- Artifact URLs must be publicly reachable or local paths

Fine for developer exploration, internal integration, and pilots. Needs hardening before multi-tenant production.

## What's next

- [`@logicpearl/try`](https://www.npmjs.com/package/@logicpearl/try) — kick the tires on the engine without writing any integration code
- [`@logicpearl/browser`](https://www.npmjs.com/package/@logicpearl/browser) — `loadArtifact()` + `evaluate()` in the browser or worker
- [MCP docs](https://logicpearl.com/developers/mcp) | [Source](https://github.com/LogicPearlHQ/logicpearl)

## License

MIT
