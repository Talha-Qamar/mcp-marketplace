# Demo MCP servers

Small but real MCP servers used by the marketplace demo, the tests and the analyzer conformance
suite. They are ingested through the same pipeline as any submitted repository (source kind
`local`), so nothing about them is special-cased in the scanner.

| Server | Language | Expected verdict | Why |
|---|---|---|---|
| `weather-tools` | Python (FastMCP) | PASS | Clean control: argv lists, no tainted value reaches a sink |
| `db-helper` | TypeScript (MCP SDK) | REVIEW | Parameterised SQL, but manipulative tool descriptions (preference manipulation) |
| `shell-runner` | Python (FastMCP) | FAIL | Two direct command injections: tool input concatenated into a shell string |

`_bait/<server>/` holds the rug-pull version of each server: the files there replace the
originals when the demo's "bait and switch" is triggered. It is never ingested on its own.

**These servers are deliberately vulnerable. Do not run them.**
