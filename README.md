# ReverseOrbit

ReverseOrbit is a local-first reverse engineering workbench for binary analysis.

It is built as a Rust workspace plus a Vite/React frontend and currently ships a real static-analysis pipeline powered by `radare2`. ReverseOrbit collects binary metadata, imports, exports, strings, functions, hot-function CFG/disassembly, xref probes, deterministic findings, next-step actions, and graph views, then stores everything as a reusable local case.

## Current Status

Implemented today:

- Rust workspace with separate crates for core domain logic, radare2 integration, MCP helpers, and the local app server
- React frontend with the `Crosure`-inspired glass/metal UI language, tabbed layout, Cytoscape graph views, and right-side analyst inspector
- Local case persistence under `.reverseorbit/cases/<case_id>/`
- Deterministic findings and follow-up actions for suspicious imports, strings, and hot functions
- REST API, WebSocket progress/events, CLI commands, and a basic MCP stdio server
- Graph exports in GraphML

Not implemented yet:

- Emulation workflows
- Interactive debugging workflows
- Additional adapters such as Ghidra or custom script engines
- Deep automated test coverage beyond the current core validation and end-to-end smoke checks

## Architecture

### Rust workspace

- `reverseorbit-core`
  Domain models, case storage, graph builders, export helpers, and deterministic playbooks.

- `reverseorbit-radare2`
  `radare2` command runner plus JSON normalization into ReverseOrbit snapshots and artifacts.

- `reverseorbit-mcp`
  Lightweight MCP protocol helpers for stdio transport.

- `reverseorbit-app`
  CLI entrypoint, HTTP API, WebSocket events, static frontend serving, and MCP tool dispatch.

### Frontend

- `web/`
  Vite + React app with Zustand state, Cytoscape + dagre graph rendering, Tailwind styling, and a `Crosure`-style operator UI.

## What ReverseOrbit Produces

For each analysis case, ReverseOrbit stores:

- `manifest.json`
- `timeline.jsonl`
- `findings.json`
- `actions.json`
- `artifacts/raw/*.json`
- `artifacts/normalized/*.json`
- `graphs/*.json`
- `exports/*.graphml`

This lives under:

```text
.reverseorbit/cases/<case_id>/
```

## Requirements

- Rust toolchain
- Node.js and npm
- `radare2`

Optional but useful:

- A sample binary such as `/bin/ls`
- Gephi, yFiles, or any GraphML-compatible tooling for exported graphs

## Quick Start

### 1. Install frontend dependencies

```bash
cd web
npm install
cd ..
```

### 2. Build and test

```bash
cargo test -q
cd web && npm run build && cd ..
```

### 3. Run a one-shot analysis

```bash
cargo run -p reverseorbit-app -- analyze /bin/ls
```

That command creates a new local case, runs baseline radare2 analysis, and prints a JSON summary.

### 4. Run the local server

```bash
cargo run -p reverseorbit-app -- server --port 4080
```

Then open:

```text
http://127.0.0.1:4080
```

### 5. Run analyze and open the UI automatically

```bash
cargo run -p reverseorbit-app -- analyze /bin/ls --open-ui --port 4080
```

## CLI Commands

### Analyze

```bash
cargo run -p reverseorbit-app -- analyze <FILE> [--profile quick|full] [--open-ui] [--cases-dir <PATH>] [--port <PORT>]
```

Current supported profiles:

- `quick`
- `full`

### Server

```bash
cargo run -p reverseorbit-app -- server [--cases-dir <PATH>] [--port <PORT>]
```

### MCP

```bash
cargo run -p reverseorbit-app -- mcp [--cases-dir <PATH>]
```

## Use With Codex

ReverseOrbit is now wired for Codex MCP in this repository via:

- `.codex/config.toml`

If the project is trusted, Codex will auto-load that MCP server entry and expose the
ReverseOrbit tools.

### Quick setup

1. Open this repository in Codex.
2. Trust the project when prompted.
3. Start a Codex session in this repo.
4. Ask Codex to list MCP tools; you should see ReverseOrbit tools like `start_case`,
   `query_findings`, and `explain_finding`.

### Optional user-level setup

If you prefer global config instead of project config, add this to
`~/.codex/config.toml`:

```toml
[mcp_servers.reverseorbit]
command = "bash"
args = [
  "-lc",
  "repo_root=\"/absolute/path/to/reverseorbit\"; app_bin=\"$repo_root/target/debug/reverseorbit-app\"; if [ -x \"$app_bin\" ]; then exec \"$app_bin\" mcp; else exec cargo run -q -p reverseorbit-app --manifest-path \"$repo_root/Cargo.toml\" -- mcp; fi"
]
cwd = "/absolute/path/to/reverseorbit"
enabled = true
required = false
startup_timeout_sec = 180
tool_timeout_sec = 180
```

Replace `/absolute/path/to/reverseorbit` with your local repository path.

Set `required = true` only if you want Codex startup to fail fast whenever the
ReverseOrbit MCP server is unavailable.

For best startup reliability, prebuild once:

```bash
cargo build -p reverseorbit-app
```

## HTTP API

ReverseOrbit currently exposes:

- `GET /health`
- `GET /api/cases`
- `POST /api/cases`
- `GET /api/cases/{id}`
- `POST /api/cases/{id}/analyze`
- `GET /api/cases/{id}/timeline`
- `GET /api/cases/{id}/findings`
- `GET /api/cases/{id}/findings/{finding_id}/explain`
- `GET /api/cases/{id}/graphs/{view}`
- `GET /api/cases/{id}/artifacts/{artifact_id}`
- `POST /api/cases/{id}/actions/{action_id}/run`
- `GET /api/cases/{id}/export`

WebSocket:

- `GET /ws`

Event types currently emitted:

- `progress`
- `step_complete`
- `finding_created`
- `graph_updated`
- `status_changed`

## MCP Tools

The stdio MCP server currently supports:

- `start_case`
- `list_cases`
- `get_case_summary`
- `get_timeline`
- `inspect_entity`
- `query_findings`
- `explain_finding`
- `get_graph_view`
- `run_next_action`
- `list_radare_commands`
- `run_radare_query`
- `search_strings_live`
- `export_case`

These are designed for Codex, Claude Code, Gemini CLI, and other MCP-capable agent tools.

Dynamic query safety notes:

- `run_radare_query` allows only read-only JSON query commands.
- commands that modify binaries, shell out, or trigger debugger control paths are rejected.
- `timeout_sec` and `max_items` can be used to bound response size and runtime for MCP sessions.

## Frontend Notes

The frontend intentionally reuses the interaction style and visual language of the earlier `Crosure` project:

- glass and metal surfaces
- keyboard-style tab buttons
- dark operator-focused layout
- Cytoscape graph canvas
- right-side inspector panel

Current tabs:

- `Overview`
- `Timeline`
- `Graphs`
- `Findings`
- `Artifacts`
- `Exports`

## Reverse Engineering Workflow

The current v1 workflow is static-analysis-first:

1. Fingerprint the binary
2. Collect sections and segments
3. Collect imports and exports
4. Collect symbols and strings
5. Analyze functions and call relationships
6. Expand a small set of hot functions with CFG and disassembly
7. Probe xrefs for suspicious imports and strings
8. Generate deterministic findings and next actions
9. Rebuild graph views and exportable artifacts

## Graph Views

ReverseOrbit currently generates these graph bundles:

- `provenance`
- `call_graph`
- `cfg`
- `xref_view`
- `string_relation_view`

These are stored as JSON for the frontend and can also be exported as GraphML.

## Development Notes

### Rust verification

```bash
cargo test -q
```

### Frontend build

```bash
cd web
npm run build
```

### Frontend dev server

```bash
cd web
npm run dev
```

The Vite dev server proxies `/api`, `/ws`, and `/health` to the local Rust server.

## Roadmap

Planned next layers:

- richer action execution and graph pivots
- more artifact inspectors and UI polish
- deeper fixture-based integration tests
- runtime emulation adapters
- debugger-backed analysis steps
- additional adapters such as Ghidra and custom tooling

## License

MIT
