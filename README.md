# agentleisure-guard

Hard limits for AI agent tools, enforced in code instead of the prompt. Node 18+.

**0 dependencies · 0 install scripts.** Installs cleanly under npm v12 defaults, with nothing to approve in `allowScripts`.

- **Human approval** for destructive actions: `DROP`/`TRUNCATE`, `UPDATE`/`DELETE` without `WHERE`, `rm -rf` and PowerShell `Remove-Item -Recurse`, force push and remote branch deletion, `curl | sh`, database resets (`prisma migrate reset`), Terraform/Kubernetes/cloud deletions, `gh repo delete`, `npm unpublish`.
- **Secret blocking**: API keys, private keys and `.env` contents never go out through a network tool.
- **Loop breaker**: stops retrying the same failing call.
- **Budget cap**: refuses a paid call before the money moves.
- **Tamper-evident journal**: every call is written as a hash-chained JSON line.
- **Untrusted text scan**: `scanUntrusted(text)` flags prompt injection in pages, issues, PR comments and tool results (override attempts, hidden characters and HTML, requests to send secrets, `curl | sh`).
- **API deletes**: HTTP `DELETE` requests and GraphQL delete mutations need approval too.
- **Credential files**: opening `.env`, SSH keys or cloud credentials needs approval (`allowSecretAccess: true` turns it off); templates like `.env.example` are fine.

```sh
npm install agentleisure-guard
```

## Local guard

```js
import { createGuard, agentLeisureApprover } from "agentleisure-guard";

const guard = createGuard({
  approve: agentLeisureApprover({ apiKey: process.env.AGENTLEISURE_KEY }), // or your own async ({ tool, args }) => boolean
  budgetUsd: 5,
  maxFailures: 2,
  secretValues: [process.env.OPENAI_API_KEY],
});

const runSql = guard.wrap("run_sql", realRunSql);
const httpPost = guard.wrap("http_post", realPost, { network: true, costUsd: 0.01 });
```

A refusal throws a `GuardError` with a `code`, so the agent gets a clear, final "no".

## MCP gateway (no code)

Put the guard in front of any stdio MCP server. Change the server command in your MCP client config:

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "agentleisure-guard", "mcp", "--journal", "agent-journal.jsonl", "--",
               "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "...", "AGENTLEISURE_KEY": "al_..." }
    }
  }
}
```

The gateway runs locally and checks every `tools/call` before the server sees it:

- **Destructive calls and credential files**: with `AGENTLEISURE_KEY` set, the call waits until a human approves it (link in the log, or in Slack or Discord via `AGENTLEISURE_NOTIFY_URL`). With no key, the call is refused and the agent is told why. `--ask allow` forwards it with a warning instead.
- **Secrets over the network**: always refused.
- **Loops**: the same call more than 10 times in 5 minutes is refused (`--loop-limit`).
- **Tool results**: text that tries to instruct the agent gets a warning in front of it.
- **Tool descriptions**: a poisoned description hides the tool; a suspicious one gets a warning.
- **Taint after injection**: once a tool result has tried to instruct the agent, any call that can send data out (network tools, commands, URLs) needs a human for the next 10 minutes. This catches the "read a poisoned PR comment, then post the keys" chain that per-call checks miss. `--no-taint` turns it off.
- **Undo**: before a call deletes, moves or overwrites local files, the gateway copies them to `~/.agentleisure/snapshots`. `agentleisure-guard undo` lists snapshots; `agentleisure-guard undo <id>` restores one, and the state it replaces is saved too. `--no-snapshot` turns it off.
- **Journal**: `--journal` writes a hash-chained line per call, which you can verify at https://agentleisure.com/safety/journal.

Arguments and results stay on your machine. Only the approval summary goes to AgentLeisure, and only when you set a key.

**Remote MCP servers** (Streamable HTTP) work too: the gateway still runs locally and connects out.

```json
"remote-tools": {
  "command": "npx",
  "args": ["-y", "agentleisure-guard", "mcp", "--url", "https://mcp.example.com/mcp", "--bearer-env", "MCP_TOKEN"],
  "env": { "MCP_TOKEN": "..." }
}
```

`--remember-approval 15` lets the exact same call through for 15 minutes after a human approved it, so you are not asked again for a retry. A different call still asks.

Other commands: `agentleisure-guard check <tool> '<json>'` and `agentleisure-guard scan <file>`.

## Hosted Guard API

The same rules as one HTTP call. Works for tools written in any language.

```js
import { checkToolCall, guardTool } from "agentleisure-guard";

await checkToolCall("run_sql", { query: "DROP TABLE users" });
// { decision: "ask", rule: "destructive", reason: "..." }

const runSql = guardTool("run_sql", realRunSql, { apiKey: process.env.AGENTLEISURE_KEY });
await runSql({ query: "DROP TABLE users" }); // waits until a human approves, throws if denied
```

Get a free key, try calls and see approval requests at https://agentleisure.com/console.
Python client: https://agentleisure.com/agentleisure_guard.py. MCP tools: https://agentleisure.com/mcp.

MIT licensed.
