#!/usr/bin/env node
// agentleisure-guard command line.
//   agentleisure-guard mcp [options] -- <command> [args...]   guard any stdio MCP server
//   agentleisure-guard mcp [options] --url <https url>         guard a remote (Streamable HTTP) MCP server
//   agentleisure-guard check <tool> <args-json>                 classify one tool call locally
//   agentleisure-guard scan <file|->                            scan untrusted text for prompt injection
import { readFileSync } from "node:fs";
import { classifyCall, scanUntrusted } from "./agent-guard.mjs";
import { runMcpGuard, runMcpGuardRemote } from "./mcp-guard.mjs";

const HELP = `agentleisure-guard: hard limits for AI agent tools

  agentleisure-guard mcp [options] -- <command> [args...]
  agentleisure-guard mcp [options] --url <https://remote-server/mcp>
      Run an MCP server behind the guard. Put this in your MCP client config instead of the server command.
      Options:
        --url <url>          guard a remote MCP server (Streamable HTTP) instead of starting a local one
        --header "N: v"      extra header for the remote server (repeatable)
        --bearer-env <VAR>   send "Authorization: Bearer <value of VAR>" to the remote server
        --remember-approval <minutes>  after a human approves a call, let the exact same call through for this long
        --journal <file>     append a hash-chained JSON line per call (verify at agentleisure.com/safety/journal)
        --ask block|allow    what to do with destructive calls when no approver is set (default: block)
        --loop-limit <n>     refuse a call repeated more than n times in 5 minutes (default 10, 0 = off)
        --no-scan            do not scan tool results and tool descriptions
      Environment:
        AGENTLEISURE_KEY        agent key from agentleisure.com/console: destructive calls wait for one-click approval
        AGENTLEISURE_NOTIFY_URL Slack or Discord webhook that receives the approval link

  agentleisure-guard check <tool> '<json args>'
  agentleisure-guard scan <file>    (use - for stdin)
`;

const [command, ...rest] = process.argv.slice(2);

if (command === "mcp") {
  const split = rest.indexOf("--");
  // Without "--", a leading non-flag word starts the server command (older usage); otherwise everything is flags.
  const bareCommand = split < 0 && rest.length > 0 && !rest[0].startsWith("--");
  const flags = split >= 0 ? rest.slice(0, split) : bareCommand ? [] : rest;
  const target = split >= 0 ? rest.slice(split + 1) : bareCommand ? rest : [];
  const options = { askMode: "block", loopLimit: 10, scan: true, journal: null, rememberApprovalMs: 0, headers: {} };
  let url = null;
  for (let index = 0; index < flags.length; index++) {
    const flag = flags[index];
    if (flag === "--journal") options.journal = flags[++index];
    else if (flag === "--ask") options.askMode = flags[++index] === "allow" ? "allow" : "block";
    else if (flag === "--loop-limit") options.loopLimit = Math.max(0, Number(flags[++index]) || 0);
    else if (flag === "--no-scan") options.scan = false;
    else if (flag === "--remember-approval") options.rememberApprovalMs = Math.max(0, Number(flags[++index]) || 0) * 60_000;
    else if (flag === "--url") url = flags[++index];
    else if (flag === "--header") {
      const raw = flags[++index] ?? ""; const colon = raw.indexOf(":");
      if (colon <= 0) { process.stderr.write(`--header needs "Name: value"
`); process.exit(2); }
      options.headers[raw.slice(0, colon).trim()] = raw.slice(colon + 1).trim();
    } else if (flag === "--bearer-env") {
      const name = flags[++index]; const value = name ? process.env[name] : undefined;
      if (!value) { process.stderr.write(`--bearer-env: environment variable ${name} is not set
`); process.exit(2); }
      options.headers.Authorization = `Bearer ${value}`;
    } else { process.stderr.write(`unknown option ${flag}
${HELP}`); process.exit(2); }
  }
  if (url) {
    try { runMcpGuardRemote(url, options); } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : error}
`); process.exit(2); }
  } else if (target.length) runMcpGuard(target[0], target.slice(1), options);
  else { process.stderr.write(HELP); process.exit(2); }
} else if (command === "check") {
  const [tool, raw = "{}"] = rest;
  let args = raw;
  try { args = JSON.parse(raw); } catch { /* plain text arguments */ }
  process.stdout.write(`${JSON.stringify(classifyCall({ tool, args }), null, 2)}\n`);
} else if (command === "scan") {
  const source = rest[0] ?? "-";
  const text = readFileSync(source === "-" ? 0 : source, "utf8");
  const result = scanUntrusted(text);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.risk === "high" ? 2 : result.risk === "medium" ? 1 : 0;
} else {
  process.stdout.write(HELP);
  process.exitCode = command && command !== "help" && command !== "--help" ? 2 : 0;
}
